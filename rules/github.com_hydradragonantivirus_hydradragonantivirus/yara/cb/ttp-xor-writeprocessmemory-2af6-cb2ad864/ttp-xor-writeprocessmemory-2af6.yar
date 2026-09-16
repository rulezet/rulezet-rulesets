rule TTP_XOR_WriteProcessMemory_2af6 {
  strings:
    $key_2af6 = { 7d 84 [2] 4f a6 [2] 49 93 [2] 67 93 [2] 58 8f }

  condition:
    any of them
}