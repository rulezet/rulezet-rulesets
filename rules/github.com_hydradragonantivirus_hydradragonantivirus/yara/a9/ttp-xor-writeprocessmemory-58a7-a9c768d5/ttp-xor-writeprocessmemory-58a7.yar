rule TTP_XOR_WriteProcessMemory_58a7 {
  strings:
    $key_58a7 = { 0f d5 [2] 3d f7 [2] 3b c2 [2] 15 c2 [2] 2a de }

  condition:
    any of them
}