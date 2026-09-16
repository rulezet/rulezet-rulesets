rule TTP_XOR_WriteProcessMemory_18d6 {
  strings:
    $key_18d6 = { 4f a4 [2] 7d 86 [2] 7b b3 [2] 55 b3 [2] 6a af }

  condition:
    any of them
}