rule TTP_XOR_WriteProcessMemory_235b {
  strings:
    $key_235b = { 74 29 [2] 46 0b [2] 40 3e [2] 6e 3e [2] 51 22 }

  condition:
    any of them
}