rule TTP_XOR_WriteProcessMemory_6368 {
  strings:
    $key_6368 = { 34 1a [2] 06 38 [2] 00 0d [2] 2e 0d [2] 11 11 }

  condition:
    any of them
}