rule TTP_XOR_WriteProcessMemory_3d71 {
  strings:
    $key_3d71 = { 6a 03 [2] 58 21 [2] 5e 14 [2] 70 14 [2] 4f 08 }

  condition:
    any of them
}