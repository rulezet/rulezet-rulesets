rule TTP_XOR_WriteProcessMemory_28d1 {
  strings:
    $key_28d1 = { 7f a3 [2] 4d 81 [2] 4b b4 [2] 65 b4 [2] 5a a8 }

  condition:
    any of them
}