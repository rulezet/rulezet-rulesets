rule TTP_XOR_WriteProcessMemory_6cc4 {
  strings:
    $key_6cc4 = { 3b b6 [2] 09 94 [2] 0f a1 [2] 21 a1 [2] 1e bd }

  condition:
    any of them
}