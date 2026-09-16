rule TTP_XOR_WriteProcessMemory_bf2e {
  strings:
    $key_bf2e = { e8 5c [2] da 7e [2] dc 4b [2] f2 4b [2] cd 57 }

  condition:
    any of them
}