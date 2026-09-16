rule TTP_XOR_WriteProcessMemory_602b {
  strings:
    $key_602b = { 37 59 [2] 05 7b [2] 03 4e [2] 2d 4e [2] 12 52 }

  condition:
    any of them
}