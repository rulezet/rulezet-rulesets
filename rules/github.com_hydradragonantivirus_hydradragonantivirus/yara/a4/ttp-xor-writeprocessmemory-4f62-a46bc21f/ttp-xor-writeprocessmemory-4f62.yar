rule TTP_XOR_WriteProcessMemory_4f62 {
  strings:
    $key_4f62 = { 18 10 [2] 2a 32 [2] 2c 07 [2] 02 07 [2] 3d 1b }

  condition:
    any of them
}