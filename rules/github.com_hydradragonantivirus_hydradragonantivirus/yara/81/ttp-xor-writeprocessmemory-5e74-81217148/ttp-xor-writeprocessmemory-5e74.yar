rule TTP_XOR_WriteProcessMemory_5e74 {
  strings:
    $key_5e74 = { 09 06 [2] 3b 24 [2] 3d 11 [2] 13 11 [2] 2c 0d }

  condition:
    any of them
}