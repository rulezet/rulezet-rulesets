rule TTP_XOR_WriteProcessMemory_9fba {
  strings:
    $key_9fba = { c8 c8 [2] fa ea [2] fc df [2] d2 df [2] ed c3 }

  condition:
    any of them
}