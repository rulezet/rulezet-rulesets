rule TTP_XOR_WriteProcessMemory_455b {
  strings:
    $key_455b = { 12 29 [2] 20 0b [2] 26 3e [2] 08 3e [2] 37 22 }

  condition:
    any of them
}