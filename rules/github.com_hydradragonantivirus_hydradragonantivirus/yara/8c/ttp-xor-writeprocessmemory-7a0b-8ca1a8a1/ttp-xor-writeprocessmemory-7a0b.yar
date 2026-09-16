rule TTP_XOR_WriteProcessMemory_7a0b {
  strings:
    $key_7a0b = { 2d 79 [2] 1f 5b [2] 19 6e [2] 37 6e [2] 08 72 }

  condition:
    any of them
}