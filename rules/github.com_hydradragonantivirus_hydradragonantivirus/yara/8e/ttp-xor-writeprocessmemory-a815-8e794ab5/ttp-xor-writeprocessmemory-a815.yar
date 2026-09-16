rule TTP_XOR_WriteProcessMemory_a815 {
  strings:
    $key_a815 = { ff 67 [2] cd 45 [2] cb 70 [2] e5 70 [2] da 6c }

  condition:
    any of them
}