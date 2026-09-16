rule TTP_XOR_WriteProcessMemory_571b {
  strings:
    $key_571b = { 00 69 [2] 32 4b [2] 34 7e [2] 1a 7e [2] 25 62 }

  condition:
    any of them
}