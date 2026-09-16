rule TTP_XOR_WriteProcessMemory_4ff8 {
  strings:
    $key_4ff8 = { 18 8a [2] 2a a8 [2] 2c 9d [2] 02 9d [2] 3d 81 }

  condition:
    any of them
}