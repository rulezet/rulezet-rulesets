rule TTP_XOR_WriteProcessMemory_5e65 {
  strings:
    $key_5e65 = { 09 17 [2] 3b 35 [2] 3d 00 [2] 13 00 [2] 2c 1c }

  condition:
    any of them
}