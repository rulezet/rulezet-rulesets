rule TTP_XOR_WriteProcessMemory_4f2b {
  strings:
    $key_4f2b = { 18 59 [2] 2a 7b [2] 2c 4e [2] 02 4e [2] 3d 52 }

  condition:
    any of them
}