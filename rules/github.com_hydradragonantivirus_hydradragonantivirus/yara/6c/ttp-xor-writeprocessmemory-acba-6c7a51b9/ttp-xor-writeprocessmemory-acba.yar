rule TTP_XOR_WriteProcessMemory_acba {
  strings:
    $key_acba = { fb c8 [2] c9 ea [2] cf df [2] e1 df [2] de c3 }

  condition:
    any of them
}