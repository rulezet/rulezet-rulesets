rule TTP_XOR_WriteProcessMemory_75d2 {
  strings:
    $key_75d2 = { 22 a0 [2] 10 82 [2] 16 b7 [2] 38 b7 [2] 07 ab }

  condition:
    any of them
}