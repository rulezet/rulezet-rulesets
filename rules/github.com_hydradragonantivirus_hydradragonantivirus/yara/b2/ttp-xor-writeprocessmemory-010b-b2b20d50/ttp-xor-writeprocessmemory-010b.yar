rule TTP_XOR_WriteProcessMemory_010b {
  strings:
    $key_010b = { 56 79 [2] 64 5b [2] 62 6e [2] 4c 6e [2] 73 72 }

  condition:
    any of them
}