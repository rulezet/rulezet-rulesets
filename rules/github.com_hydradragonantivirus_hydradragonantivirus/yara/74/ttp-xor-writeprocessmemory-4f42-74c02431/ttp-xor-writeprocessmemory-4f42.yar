rule TTP_XOR_WriteProcessMemory_4f42 {
  strings:
    $key_4f42 = { 18 30 [2] 2a 12 [2] 2c 27 [2] 02 27 [2] 3d 3b }

  condition:
    any of them
}