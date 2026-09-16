rule TTP_XOR_WriteProcessMemory_766b {
  strings:
    $key_766b = { 21 19 [2] 13 3b [2] 15 0e [2] 3b 0e [2] 04 12 }

  condition:
    any of them
}