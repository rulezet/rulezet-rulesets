rule TTP_XOR_WriteProcessMemory_5ef8 {
  strings:
    $key_5ef8 = { 09 8a [2] 3b a8 [2] 3d 9d [2] 13 9d [2] 2c 81 }

  condition:
    any of them
}