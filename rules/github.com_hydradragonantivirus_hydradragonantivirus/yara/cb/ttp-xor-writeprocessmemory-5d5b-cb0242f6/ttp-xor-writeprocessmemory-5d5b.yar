rule TTP_XOR_WriteProcessMemory_5d5b {
  strings:
    $key_5d5b = { 0a 29 [2] 38 0b [2] 3e 3e [2] 10 3e [2] 2f 22 }

  condition:
    any of them
}