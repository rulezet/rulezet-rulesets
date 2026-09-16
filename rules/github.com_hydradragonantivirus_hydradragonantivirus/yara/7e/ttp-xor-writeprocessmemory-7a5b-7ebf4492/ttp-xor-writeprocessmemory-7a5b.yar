rule TTP_XOR_WriteProcessMemory_7a5b {
  strings:
    $key_7a5b = { 2d 29 [2] 1f 0b [2] 19 3e [2] 37 3e [2] 08 22 }

  condition:
    any of them
}