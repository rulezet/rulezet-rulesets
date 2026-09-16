rule TTP_XOR_WriteProcessMemory_386b {
  strings:
    $key_386b = { 6f 19 [2] 5d 3b [2] 5b 0e [2] 75 0e [2] 4a 12 }

  condition:
    any of them
}