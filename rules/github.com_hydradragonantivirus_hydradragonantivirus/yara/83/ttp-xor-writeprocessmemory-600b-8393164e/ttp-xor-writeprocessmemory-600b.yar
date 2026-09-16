rule TTP_XOR_WriteProcessMemory_600b {
  strings:
    $key_600b = { 37 79 [2] 05 5b [2] 03 6e [2] 2d 6e [2] 12 72 }

  condition:
    any of them
}