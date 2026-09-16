rule TTP_XOR_WriteProcessMemory_5e1b {
  strings:
    $key_5e1b = { 09 69 [2] 3b 4b [2] 3d 7e [2] 13 7e [2] 2c 62 }

  condition:
    any of them
}