rule TTP_XOR_WriteProcessMemory_6a90 {
  strings:
    $key_6a90 = { 3d e2 [2] 0f c0 [2] 09 f5 [2] 27 f5 [2] 18 e9 }

  condition:
    any of them
}