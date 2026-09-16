rule TTP_XOR_WriteProcessMemory_152b {
  strings:
    $key_152b = { 42 59 [2] 70 7b [2] 76 4e [2] 58 4e [2] 67 52 }

  condition:
    any of them
}