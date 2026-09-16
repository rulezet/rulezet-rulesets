rule TTP_XOR_WriteProcessMemory_2a66 {
  strings:
    $key_2a66 = { 7d 14 [2] 4f 36 [2] 49 03 [2] 67 03 [2] 58 1f }

  condition:
    any of them
}