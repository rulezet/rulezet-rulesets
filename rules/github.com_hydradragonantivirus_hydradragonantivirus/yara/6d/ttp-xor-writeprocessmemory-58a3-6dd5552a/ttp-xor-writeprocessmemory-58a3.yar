rule TTP_XOR_WriteProcessMemory_58a3 {
  strings:
    $key_58a3 = { 0f d1 [2] 3d f3 [2] 3b c6 [2] 15 c6 [2] 2a da }

  condition:
    any of them
}