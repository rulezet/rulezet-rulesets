rule TTP_XOR_WriteProcessMemory_186b {
  strings:
    $key_186b = { 4f 19 [2] 7d 3b [2] 7b 0e [2] 55 0e [2] 6a 12 }

  condition:
    any of them
}