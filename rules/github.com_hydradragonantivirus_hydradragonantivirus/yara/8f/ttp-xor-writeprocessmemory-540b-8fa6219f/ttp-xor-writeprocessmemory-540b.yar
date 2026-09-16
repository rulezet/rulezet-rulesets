rule TTP_XOR_WriteProcessMemory_540b {
  strings:
    $key_540b = { 03 79 [2] 31 5b [2] 37 6e [2] 19 6e [2] 26 72 }

  condition:
    any of them
}