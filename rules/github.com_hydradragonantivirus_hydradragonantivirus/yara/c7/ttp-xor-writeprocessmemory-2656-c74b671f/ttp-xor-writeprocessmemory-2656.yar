rule TTP_XOR_WriteProcessMemory_2656 {
  strings:
    $key_2656 = { 71 24 [2] 43 06 [2] 45 33 [2] 6b 33 [2] 54 2f }

  condition:
    any of them
}