rule TTP_XOR_WriteProcessMemory_5cc4 {
  strings:
    $key_5cc4 = { 0b b6 [2] 39 94 [2] 3f a1 [2] 11 a1 [2] 2e bd }

  condition:
    any of them
}