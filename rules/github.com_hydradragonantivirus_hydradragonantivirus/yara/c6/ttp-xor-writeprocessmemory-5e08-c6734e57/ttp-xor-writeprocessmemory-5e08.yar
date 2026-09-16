rule TTP_XOR_WriteProcessMemory_5e08 {
  strings:
    $key_5e08 = { 09 7a [2] 3b 58 [2] 3d 6d [2] 13 6d [2] 2c 71 }

  condition:
    any of them
}