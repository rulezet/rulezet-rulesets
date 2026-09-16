rule TTP_XOR_WriteProcessMemory_4e2b {
  strings:
    $key_4e2b = { 19 59 [2] 2b 7b [2] 2d 4e [2] 03 4e [2] 3c 52 }

  condition:
    any of them
}