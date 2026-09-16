rule TTP_XOR_WriteProcessMemory_4f5b {
  strings:
    $key_4f5b = { 18 29 [2] 2a 0b [2] 2c 3e [2] 02 3e [2] 3d 22 }

  condition:
    any of them
}