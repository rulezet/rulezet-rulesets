rule TTP_XOR_WriteProcessMemory_13d2 {
  strings:
    $key_13d2 = { 44 a0 [2] 76 82 [2] 70 b7 [2] 5e b7 [2] 61 ab }

  condition:
    any of them
}