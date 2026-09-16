rule TTP_XOR_WriteProcessMemory_803f {
  strings:
    $key_803f = { d7 4d [2] e5 6f [2] e3 5a [2] cd 5a [2] f2 46 }

  condition:
    any of them
}