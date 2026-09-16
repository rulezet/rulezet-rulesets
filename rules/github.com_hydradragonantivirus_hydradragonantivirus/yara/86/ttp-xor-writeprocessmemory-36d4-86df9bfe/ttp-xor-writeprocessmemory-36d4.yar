rule TTP_XOR_WriteProcessMemory_36d4 {
  strings:
    $key_36d4 = { 61 a6 [2] 53 84 [2] 55 b1 [2] 7b b1 [2] 44 ad }

  condition:
    any of them
}