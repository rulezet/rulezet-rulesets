rule TTP_XOR_WriteProcessMemory_2a56 {
  strings:
    $key_2a56 = { 7d 24 [2] 4f 06 [2] 49 33 [2] 67 33 [2] 58 2f }

  condition:
    any of them
}