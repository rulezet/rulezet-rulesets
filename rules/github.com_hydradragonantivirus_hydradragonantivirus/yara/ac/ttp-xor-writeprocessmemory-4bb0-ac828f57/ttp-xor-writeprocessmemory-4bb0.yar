rule TTP_XOR_WriteProcessMemory_4bb0 {
  strings:
    $key_4bb0 = { 1c c2 [2] 2e e0 [2] 28 d5 [2] 06 d5 [2] 39 c9 }

  condition:
    any of them
}