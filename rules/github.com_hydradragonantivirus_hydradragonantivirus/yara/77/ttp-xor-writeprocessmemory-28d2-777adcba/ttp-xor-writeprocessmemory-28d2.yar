rule TTP_XOR_WriteProcessMemory_28d2 {
  strings:
    $key_28d2 = { 7f a0 [2] 4d 82 [2] 4b b7 [2] 65 b7 [2] 5a ab }

  condition:
    any of them
}