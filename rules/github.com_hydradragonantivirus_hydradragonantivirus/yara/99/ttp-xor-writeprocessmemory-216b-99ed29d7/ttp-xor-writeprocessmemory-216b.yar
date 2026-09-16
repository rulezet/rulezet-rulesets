rule TTP_XOR_WriteProcessMemory_216b {
  strings:
    $key_216b = { 76 19 [2] 44 3b [2] 42 0e [2] 6c 0e [2] 53 12 }

  condition:
    any of them
}