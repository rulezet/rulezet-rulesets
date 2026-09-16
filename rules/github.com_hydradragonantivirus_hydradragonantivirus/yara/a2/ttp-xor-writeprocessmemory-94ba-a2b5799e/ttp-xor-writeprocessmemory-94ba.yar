rule TTP_XOR_WriteProcessMemory_94ba {
  strings:
    $key_94ba = { c3 c8 [2] f1 ea [2] f7 df [2] d9 df [2] e6 c3 }

  condition:
    any of them
}