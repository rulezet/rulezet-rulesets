rule TTP_XOR_WriteProcessMemory_36d1 {
  strings:
    $key_36d1 = { 61 a3 [2] 53 81 [2] 55 b4 [2] 7b b4 [2] 44 a8 }

  condition:
    any of them
}