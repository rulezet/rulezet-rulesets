rule TTP_XOR_WriteProcessMemory_123d {
  strings:
    $key_123d = { 45 4f [2] 77 6d [2] 71 58 [2] 5f 58 [2] 60 44 }

  condition:
    any of them
}