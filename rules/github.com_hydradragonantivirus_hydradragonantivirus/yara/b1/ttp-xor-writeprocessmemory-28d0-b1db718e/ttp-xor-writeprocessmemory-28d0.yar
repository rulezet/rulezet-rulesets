rule TTP_XOR_WriteProcessMemory_28d0 {
  strings:
    $key_28d0 = { 7f a2 [2] 4d 80 [2] 4b b5 [2] 65 b5 [2] 5a a9 }

  condition:
    any of them
}