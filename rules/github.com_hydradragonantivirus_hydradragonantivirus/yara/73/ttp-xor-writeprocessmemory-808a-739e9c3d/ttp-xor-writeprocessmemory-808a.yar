rule TTP_XOR_WriteProcessMemory_808a {
  strings:
    $key_808a = { d7 f8 [2] e5 da [2] e3 ef [2] cd ef [2] f2 f3 }

  condition:
    any of them
}