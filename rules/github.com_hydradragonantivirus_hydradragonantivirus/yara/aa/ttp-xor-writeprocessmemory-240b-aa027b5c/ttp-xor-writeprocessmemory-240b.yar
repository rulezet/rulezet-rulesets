rule TTP_XOR_WriteProcessMemory_240b {
  strings:
    $key_240b = { 73 79 [2] 41 5b [2] 47 6e [2] 69 6e [2] 56 72 }

  condition:
    any of them
}