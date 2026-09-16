rule TTP_XOR_WriteProcessMemory_6f5b {
  strings:
    $key_6f5b = { 38 29 [2] 0a 0b [2] 0c 3e [2] 22 3e [2] 1d 22 }

  condition:
    any of them
}