rule TTP_XOR_WriteProcessMemory_4f60 {
  strings:
    $key_4f60 = { 18 12 [2] 2a 30 [2] 2c 05 [2] 02 05 [2] 3d 19 }

  condition:
    any of them
}