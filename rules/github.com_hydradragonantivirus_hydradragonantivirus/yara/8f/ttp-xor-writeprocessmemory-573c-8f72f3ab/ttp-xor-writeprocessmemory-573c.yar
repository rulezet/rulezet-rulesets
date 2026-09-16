rule TTP_XOR_WriteProcessMemory_573c {
  strings:
    $key_573c = { 00 4e [2] 32 6c [2] 34 59 [2] 1a 59 [2] 25 45 }

  condition:
    any of them
}