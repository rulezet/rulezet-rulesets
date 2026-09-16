rule TTP_XOR_WriteProcessMemory_5bb0 {
  strings:
    $key_5bb0 = { 0c c2 [2] 3e e0 [2] 38 d5 [2] 16 d5 [2] 29 c9 }

  condition:
    any of them
}