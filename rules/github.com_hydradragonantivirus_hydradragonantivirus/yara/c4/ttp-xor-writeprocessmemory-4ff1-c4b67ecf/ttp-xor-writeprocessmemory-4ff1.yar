rule TTP_XOR_WriteProcessMemory_4ff1 {
  strings:
    $key_4ff1 = { 18 83 [2] 2a a1 [2] 2c 94 [2] 02 94 [2] 3d 88 }

  condition:
    any of them
}