rule TTP_XOR_WriteProcessMemory_0b2b {
  strings:
    $key_0b2b = { 5c 59 [2] 6e 7b [2] 68 4e [2] 46 4e [2] 79 52 }

  condition:
    any of them
}