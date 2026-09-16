rule TTP_XOR_WriteProcessMemory_a8b5 {
  strings:
    $key_a8b5 = { ff c7 [2] cd e5 [2] cb d0 [2] e5 d0 [2] da cc }

  condition:
    any of them
}