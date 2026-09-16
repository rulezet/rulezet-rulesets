rule TTP_XOR_WriteProcessMemory_185b {
  strings:
    $key_185b = { 4f 29 [2] 7d 0b [2] 7b 3e [2] 55 3e [2] 6a 22 }

  condition:
    any of them
}