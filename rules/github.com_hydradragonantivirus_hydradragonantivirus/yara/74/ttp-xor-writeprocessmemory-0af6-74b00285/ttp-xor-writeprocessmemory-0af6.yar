rule TTP_XOR_WriteProcessMemory_0af6 {
  strings:
    $key_0af6 = { 5d 84 [2] 6f a6 [2] 69 93 [2] 47 93 [2] 78 8f }

  condition:
    any of them
}