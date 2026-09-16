rule TTP_XOR_WriteProcessMemory_5e34 {
  strings:
    $key_5e34 = { 09 46 [2] 3b 64 [2] 3d 51 [2] 13 51 [2] 2c 4d }

  condition:
    any of them
}