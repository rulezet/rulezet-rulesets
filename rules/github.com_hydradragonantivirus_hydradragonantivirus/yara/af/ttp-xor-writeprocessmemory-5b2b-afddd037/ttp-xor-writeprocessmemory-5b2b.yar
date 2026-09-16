rule TTP_XOR_WriteProcessMemory_5b2b {
  strings:
    $key_5b2b = { 0c 59 [2] 3e 7b [2] 38 4e [2] 16 4e [2] 29 52 }

  condition:
    any of them
}