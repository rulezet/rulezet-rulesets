rule TTP_XOR_WriteProcessMemory_603b {
  strings:
    $key_603b = { 37 49 [2] 05 6b [2] 03 5e [2] 2d 5e [2] 12 42 }

  condition:
    any of them
}