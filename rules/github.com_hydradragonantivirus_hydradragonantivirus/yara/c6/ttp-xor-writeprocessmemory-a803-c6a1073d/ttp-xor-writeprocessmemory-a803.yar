rule TTP_XOR_WriteProcessMemory_a803 {
  strings:
    $key_a803 = { ff 71 [2] cd 53 [2] cb 66 [2] e5 66 [2] da 7a }

  condition:
    any of them
}