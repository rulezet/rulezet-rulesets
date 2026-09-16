rule TTP_XOR_WriteProcessMemory_5e78 {
  strings:
    $key_5e78 = { 09 0a [2] 3b 28 [2] 3d 1d [2] 13 1d [2] 2c 01 }

  condition:
    any of them
}