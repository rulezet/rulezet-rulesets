rule TTP_XOR_WriteProcessMemory_5ee8 {
  strings:
    $key_5ee8 = { 09 9a [2] 3b b8 [2] 3d 8d [2] 13 8d [2] 2c 91 }

  condition:
    any of them
}