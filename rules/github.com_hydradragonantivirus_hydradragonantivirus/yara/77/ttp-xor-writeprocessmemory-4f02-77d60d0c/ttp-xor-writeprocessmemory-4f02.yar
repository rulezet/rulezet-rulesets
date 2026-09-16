rule TTP_XOR_WriteProcessMemory_4f02 {
  strings:
    $key_4f02 = { 18 70 [2] 2a 52 [2] 2c 67 [2] 02 67 [2] 3d 7b }

  condition:
    any of them
}