rule TTP_XOR_WriteProcessMemory_a805 {
  strings:
    $key_a805 = { ff 77 [2] cd 55 [2] cb 60 [2] e5 60 [2] da 7c }

  condition:
    any of them
}