rule TTP_XOR_WriteProcessMemory_1bb1 {
  strings:
    $key_1bb1 = { 4c c3 [2] 7e e1 [2] 78 d4 [2] 56 d4 [2] 69 c8 }

  condition:
    any of them
}