rule TTP_XOR_WriteProcessMemory_38d2 {
  strings:
    $key_38d2 = { 6f a0 [2] 5d 82 [2] 5b b7 [2] 75 b7 [2] 4a ab }

  condition:
    any of them
}