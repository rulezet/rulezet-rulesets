rule TTP_XOR_WriteProcessMemory_806e {
  strings:
    $key_806e = { d7 1c [2] e5 3e [2] e3 0b [2] cd 0b [2] f2 17 }

  condition:
    any of them
}