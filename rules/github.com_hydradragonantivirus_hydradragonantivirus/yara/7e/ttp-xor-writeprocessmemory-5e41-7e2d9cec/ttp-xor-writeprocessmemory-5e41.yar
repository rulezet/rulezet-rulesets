rule TTP_XOR_WriteProcessMemory_5e41 {
  strings:
    $key_5e41 = { 09 33 [2] 3b 11 [2] 3d 24 [2] 13 24 [2] 2c 38 }

  condition:
    any of them
}