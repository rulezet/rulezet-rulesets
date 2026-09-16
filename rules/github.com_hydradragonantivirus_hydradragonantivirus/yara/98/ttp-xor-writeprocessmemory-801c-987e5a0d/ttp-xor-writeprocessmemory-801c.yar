rule TTP_XOR_WriteProcessMemory_801c {
  strings:
    $key_801c = { d7 6e [2] e5 4c [2] e3 79 [2] cd 79 [2] f2 65 }

  condition:
    any of them
}