rule TTP_XOR_WriteProcessMemory_6a81 {
  strings:
    $key_6a81 = { 3d f3 [2] 0f d1 [2] 09 e4 [2] 27 e4 [2] 18 f8 }

  condition:
    any of them
}