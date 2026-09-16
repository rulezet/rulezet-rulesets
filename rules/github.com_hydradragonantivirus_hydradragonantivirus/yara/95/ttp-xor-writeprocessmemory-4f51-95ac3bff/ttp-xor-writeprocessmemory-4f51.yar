rule TTP_XOR_WriteProcessMemory_4f51 {
  strings:
    $key_4f51 = { 18 23 [2] 2a 01 [2] 2c 34 [2] 02 34 [2] 3d 28 }

  condition:
    any of them
}