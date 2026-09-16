rule TTP_XOR_WriteProcessMemory_3c42 {
  strings:
    $key_3c42 = { 6b 30 [2] 59 12 [2] 5f 27 [2] 71 27 [2] 4e 3b }

  condition:
    any of them
}