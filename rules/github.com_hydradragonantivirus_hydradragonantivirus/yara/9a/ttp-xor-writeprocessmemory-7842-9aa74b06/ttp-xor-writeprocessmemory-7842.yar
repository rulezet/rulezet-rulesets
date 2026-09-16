rule TTP_XOR_WriteProcessMemory_7842 {
  strings:
    $key_7842 = { 2f 30 [2] 1d 12 [2] 1b 27 [2] 35 27 [2] 0a 3b }

  condition:
    any of them
}