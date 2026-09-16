rule TTP_XOR_WriteProcessMemory_02c1 {
  strings:
    $key_02c1 = { 55 b3 [2] 67 91 [2] 61 a4 [2] 4f a4 [2] 70 b8 }

  condition:
    any of them
}