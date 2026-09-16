rule TTP_XOR_WriteProcessMemory_5bb1 {
  strings:
    $key_5bb1 = { 0c c3 [2] 3e e1 [2] 38 d4 [2] 16 d4 [2] 29 c8 }

  condition:
    any of them
}