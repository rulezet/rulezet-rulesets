rule TTP_XOR_WriteProcessMemory_96ba {
  strings:
    $key_96ba = { c1 c8 [2] f3 ea [2] f5 df [2] db df [2] e4 c3 }

  condition:
    any of them
}