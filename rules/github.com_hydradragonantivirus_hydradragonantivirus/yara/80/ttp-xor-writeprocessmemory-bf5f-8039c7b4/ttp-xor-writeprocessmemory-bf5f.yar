rule TTP_XOR_WriteProcessMemory_bf5f {
  strings:
    $key_bf5f = { e8 2d [2] da 0f [2] dc 3a [2] f2 3a [2] cd 26 }

  condition:
    any of them
}