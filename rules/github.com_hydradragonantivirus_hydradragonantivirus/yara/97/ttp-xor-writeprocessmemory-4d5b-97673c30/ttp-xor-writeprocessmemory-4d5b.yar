rule TTP_XOR_WriteProcessMemory_4d5b {
  strings:
    $key_4d5b = { 1a 29 [2] 28 0b [2] 2e 3e [2] 00 3e [2] 3f 22 }

  condition:
    any of them
}