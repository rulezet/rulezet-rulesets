rule TTP_XOR_WriteProcessMemory_576e {
  strings:
    $key_576e = { 00 1c [2] 32 3e [2] 34 0b [2] 1a 0b [2] 25 17 }

  condition:
    any of them
}