rule TTP_XOR_WriteProcessMemory_453b {
  strings:
    $key_453b = { 12 49 [2] 20 6b [2] 26 5e [2] 08 5e [2] 37 42 }

  condition:
    any of them
}