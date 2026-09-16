rule TTP_XOR_WriteProcessMemory_4f58 {
  strings:
    $key_4f58 = { 18 2a [2] 2a 08 [2] 2c 3d [2] 02 3d [2] 3d 21 }

  condition:
    any of them
}