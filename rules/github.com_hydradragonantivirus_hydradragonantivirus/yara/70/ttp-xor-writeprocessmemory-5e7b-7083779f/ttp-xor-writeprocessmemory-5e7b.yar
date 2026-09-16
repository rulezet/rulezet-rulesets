rule TTP_XOR_WriteProcessMemory_5e7b {
  strings:
    $key_5e7b = { 09 09 [2] 3b 2b [2] 3d 1e [2] 13 1e [2] 2c 02 }

  condition:
    any of them
}