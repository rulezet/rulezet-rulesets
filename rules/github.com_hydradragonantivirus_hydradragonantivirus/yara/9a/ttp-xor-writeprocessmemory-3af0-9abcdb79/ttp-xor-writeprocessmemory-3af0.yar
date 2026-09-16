rule TTP_XOR_WriteProcessMemory_3af0 {
  strings:
    $key_3af0 = { 6d 82 [2] 5f a0 [2] 59 95 [2] 77 95 [2] 48 89 }

  condition:
    any of them
}