rule TTP_XOR_WriteProcessMemory_4f68 {
  strings:
    $key_4f68 = { 18 1a [2] 2a 38 [2] 2c 0d [2] 02 0d [2] 3d 11 }

  condition:
    any of them
}