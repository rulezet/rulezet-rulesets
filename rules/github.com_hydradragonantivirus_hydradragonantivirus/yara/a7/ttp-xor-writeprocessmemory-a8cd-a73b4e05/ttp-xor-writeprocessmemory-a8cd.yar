rule TTP_XOR_WriteProcessMemory_a8cd {
  strings:
    $key_a8cd = { ff bf [2] cd 9d [2] cb a8 [2] e5 a8 [2] da b4 }

  condition:
    any of them
}