rule TTP_XOR_WriteProcessMemory_1bb0 {
  strings:
    $key_1bb0 = { 4c c2 [2] 7e e0 [2] 78 d5 [2] 56 d5 [2] 69 c9 }

  condition:
    any of them
}