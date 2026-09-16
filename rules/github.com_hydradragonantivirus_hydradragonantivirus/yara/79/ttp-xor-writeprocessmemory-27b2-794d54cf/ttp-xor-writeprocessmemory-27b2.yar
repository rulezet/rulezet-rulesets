rule TTP_XOR_WriteProcessMemory_27b2 {
  strings:
    $key_27b2 = { 70 c0 [2] 42 e2 [2] 44 d7 [2] 6a d7 [2] 55 cb }

  condition:
    any of them
}