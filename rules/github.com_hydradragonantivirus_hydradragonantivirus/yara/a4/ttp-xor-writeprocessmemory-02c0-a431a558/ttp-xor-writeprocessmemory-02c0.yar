rule TTP_XOR_WriteProcessMemory_02c0 {
  strings:
    $key_02c0 = { 55 b2 [2] 67 90 [2] 61 a5 [2] 4f a5 [2] 70 b9 }

  condition:
    any of them
}