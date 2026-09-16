rule TTP_XOR_WriteProcessMemory_78d2 {
  strings:
    $key_78d2 = { 2f a0 [2] 1d 82 [2] 1b b7 [2] 35 b7 [2] 0a ab }

  condition:
    any of them
}