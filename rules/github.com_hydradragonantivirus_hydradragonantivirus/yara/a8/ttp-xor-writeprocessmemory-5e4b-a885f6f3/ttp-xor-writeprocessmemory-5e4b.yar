rule TTP_XOR_WriteProcessMemory_5e4b {
  strings:
    $key_5e4b = { 09 39 [2] 3b 1b [2] 3d 2e [2] 13 2e [2] 2c 32 }

  condition:
    any of them
}