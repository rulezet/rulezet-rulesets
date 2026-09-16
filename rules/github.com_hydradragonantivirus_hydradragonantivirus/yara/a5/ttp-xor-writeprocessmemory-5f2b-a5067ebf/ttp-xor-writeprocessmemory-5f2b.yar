rule TTP_XOR_WriteProcessMemory_5f2b {
  strings:
    $key_5f2b = { 08 59 [2] 3a 7b [2] 3c 4e [2] 12 4e [2] 2d 52 }

  condition:
    any of them
}