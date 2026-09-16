rule TTP_XOR_WriteProcessMemory_805a {
  strings:
    $key_805a = { d7 28 [2] e5 0a [2] e3 3f [2] cd 3f [2] f2 23 }

  condition:
    any of them
}