rule TTP_XOR_WriteProcessMemory_5e3b {
  strings:
    $key_5e3b = { 09 49 [2] 3b 6b [2] 3d 5e [2] 13 5e [2] 2c 42 }

  condition:
    any of them
}