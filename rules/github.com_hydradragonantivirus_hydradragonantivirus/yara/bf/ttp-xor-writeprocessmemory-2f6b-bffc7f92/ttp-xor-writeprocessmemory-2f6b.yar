rule TTP_XOR_WriteProcessMemory_2f6b {
  strings:
    $key_2f6b = { 78 19 [2] 4a 3b [2] 4c 0e [2] 62 0e [2] 5d 12 }

  condition:
    any of them
}