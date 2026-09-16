rule TTP_XOR_WriteProcessMemory_5c2b {
  strings:
    $key_5c2b = { 0b 59 [2] 39 7b [2] 3f 4e [2] 11 4e [2] 2e 52 }

  condition:
    any of them
}