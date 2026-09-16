rule TTP_XOR_WriteProcessMemory_a8ae {
  strings:
    $key_a8ae = { ff dc [2] cd fe [2] cb cb [2] e5 cb [2] da d7 }

  condition:
    any of them
}