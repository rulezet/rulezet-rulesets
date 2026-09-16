rule TTP_XOR_WriteProcessMemory_5042 {
  strings:
    $key_5042 = { 07 30 [2] 35 12 [2] 33 27 [2] 1d 27 [2] 22 3b }

  condition:
    any of them
}