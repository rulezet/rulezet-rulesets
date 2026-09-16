rule TTP_XOR_WriteProcessMemory_4e1b {
  strings:
    $key_4e1b = { 19 69 [2] 2b 4b [2] 2d 7e [2] 03 7e [2] 3c 62 }

  condition:
    any of them
}