rule TTP_XOR_WriteProcessMemory_4f01 {
  strings:
    $key_4f01 = { 18 73 [2] 2a 51 [2] 2c 64 [2] 02 64 [2] 3d 78 }

  condition:
    any of them
}