rule TTP_XOR_WriteProcessMemory_a8bf {
  strings:
    $key_a8bf = { ff cd [2] cd ef [2] cb da [2] e5 da [2] da c6 }

  condition:
    any of them
}