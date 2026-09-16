rule TTP_XOR_WriteProcessMemory_a8be {
  strings:
    $key_a8be = { ff cc [2] cd ee [2] cb db [2] e5 db [2] da c7 }

  condition:
    any of them
}