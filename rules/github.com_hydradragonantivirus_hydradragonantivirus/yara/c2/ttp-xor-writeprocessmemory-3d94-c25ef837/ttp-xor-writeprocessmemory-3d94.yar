rule TTP_XOR_WriteProcessMemory_3d94 {
  strings:
    $key_3d94 = { 6a e6 [2] 58 c4 [2] 5e f1 [2] 70 f1 [2] 4f ed }

  condition:
    any of them
}