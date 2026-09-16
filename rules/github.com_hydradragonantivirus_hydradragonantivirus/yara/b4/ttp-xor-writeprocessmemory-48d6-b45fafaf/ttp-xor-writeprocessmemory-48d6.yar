rule TTP_XOR_WriteProcessMemory_48d6 {
  strings:
    $key_48d6 = { 1f a4 [2] 2d 86 [2] 2b b3 [2] 05 b3 [2] 3a af }

  condition:
    any of them
}