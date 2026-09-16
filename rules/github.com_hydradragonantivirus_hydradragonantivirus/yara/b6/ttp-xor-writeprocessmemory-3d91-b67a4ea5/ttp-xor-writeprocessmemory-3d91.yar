rule TTP_XOR_WriteProcessMemory_3d91 {
  strings:
    $key_3d91 = { 6a e3 [2] 58 c1 [2] 5e f4 [2] 70 f4 [2] 4f e8 }

  condition:
    any of them
}