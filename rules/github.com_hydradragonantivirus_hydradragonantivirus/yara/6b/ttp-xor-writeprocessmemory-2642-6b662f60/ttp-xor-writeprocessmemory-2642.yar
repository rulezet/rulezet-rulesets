rule TTP_XOR_WriteProcessMemory_2642 {
  strings:
    $key_2642 = { 71 30 [2] 43 12 [2] 45 27 [2] 6b 27 [2] 54 3b }

  condition:
    any of them
}