rule TTP_XOR_WriteProcessMemory_3d72 {
  strings:
    $key_3d72 = { 6a 00 [2] 58 22 [2] 5e 17 [2] 70 17 [2] 4f 0b }

  condition:
    any of them
}