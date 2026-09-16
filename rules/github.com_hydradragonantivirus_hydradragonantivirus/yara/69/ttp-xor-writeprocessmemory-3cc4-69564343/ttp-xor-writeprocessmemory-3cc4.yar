rule TTP_XOR_WriteProcessMemory_3cc4 {
  strings:
    $key_3cc4 = { 6b b6 [2] 59 94 [2] 5f a1 [2] 71 a1 [2] 4e bd }

  condition:
    any of them
}