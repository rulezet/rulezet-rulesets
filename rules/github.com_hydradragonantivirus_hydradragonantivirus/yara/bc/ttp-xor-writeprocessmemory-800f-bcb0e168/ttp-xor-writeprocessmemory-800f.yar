rule TTP_XOR_WriteProcessMemory_800f {
  strings:
    $key_800f = { d7 7d [2] e5 5f [2] e3 6a [2] cd 6a [2] f2 76 }

  condition:
    any of them
}