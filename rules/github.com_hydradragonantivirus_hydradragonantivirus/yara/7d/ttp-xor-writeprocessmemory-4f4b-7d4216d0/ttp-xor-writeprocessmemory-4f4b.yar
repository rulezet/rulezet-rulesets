rule TTP_XOR_WriteProcessMemory_4f4b {
  strings:
    $key_4f4b = { 18 39 [2] 2a 1b [2] 2c 2e [2] 02 2e [2] 3d 32 }

  condition:
    any of them
}