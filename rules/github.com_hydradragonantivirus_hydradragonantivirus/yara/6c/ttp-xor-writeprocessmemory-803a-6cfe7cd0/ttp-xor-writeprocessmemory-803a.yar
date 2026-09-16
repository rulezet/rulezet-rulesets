rule TTP_XOR_WriteProcessMemory_803a {
  strings:
    $key_803a = { d7 48 [2] e5 6a [2] e3 5f [2] cd 5f [2] f2 43 }

  condition:
    any of them
}