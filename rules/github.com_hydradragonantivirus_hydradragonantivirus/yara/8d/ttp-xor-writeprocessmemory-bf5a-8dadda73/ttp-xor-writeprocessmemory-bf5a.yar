rule TTP_XOR_WriteProcessMemory_bf5a {
  strings:
    $key_bf5a = { e8 28 [2] da 0a [2] dc 3f [2] f2 3f [2] cd 23 }

  condition:
    any of them
}