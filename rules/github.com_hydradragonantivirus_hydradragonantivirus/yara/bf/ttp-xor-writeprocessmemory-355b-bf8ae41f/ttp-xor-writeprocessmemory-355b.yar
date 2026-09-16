rule TTP_XOR_WriteProcessMemory_355b {
  strings:
    $key_355b = { 62 29 [2] 50 0b [2] 56 3e [2] 78 3e [2] 47 22 }

  condition:
    any of them
}