rule TTP_XOR_WriteProcessMemory_3d96 {
  strings:
    $key_3d96 = { 6a e4 [2] 58 c6 [2] 5e f3 [2] 70 f3 [2] 4f ef }

  condition:
    any of them
}