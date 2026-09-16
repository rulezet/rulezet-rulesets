rule TTP_XOR_WriteProcessMemory_a809 {
  strings:
    $key_a809 = { ff 7b [2] cd 59 [2] cb 6c [2] e5 6c [2] da 70 }

  condition:
    any of them
}