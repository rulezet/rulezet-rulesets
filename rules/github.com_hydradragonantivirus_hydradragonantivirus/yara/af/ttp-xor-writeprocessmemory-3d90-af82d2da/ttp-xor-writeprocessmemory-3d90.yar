rule TTP_XOR_WriteProcessMemory_3d90 {
  strings:
    $key_3d90 = { 6a e2 [2] 58 c0 [2] 5e f5 [2] 70 f5 [2] 4f e9 }

  condition:
    any of them
}