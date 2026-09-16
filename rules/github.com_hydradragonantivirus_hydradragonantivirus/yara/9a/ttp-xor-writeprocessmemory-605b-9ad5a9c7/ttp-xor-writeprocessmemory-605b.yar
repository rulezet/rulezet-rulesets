rule TTP_XOR_WriteProcessMemory_605b {
  strings:
    $key_605b = { 37 29 [2] 05 0b [2] 03 3e [2] 2d 3e [2] 12 22 }

  condition:
    any of them
}