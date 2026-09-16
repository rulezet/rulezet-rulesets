rule TTP_XOR_WriteProcessMemory_26d1 {
  strings:
    $key_26d1 = { 71 a3 [2] 43 81 [2] 45 b4 [2] 6b b4 [2] 54 a8 }

  condition:
    any of them
}