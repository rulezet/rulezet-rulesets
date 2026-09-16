rule TTP_XOR_WriteProcessMemory_4f1b {
  strings:
    $key_4f1b = { 18 69 [2] 2a 4b [2] 2c 7e [2] 02 7e [2] 3d 62 }

  condition:
    any of them
}