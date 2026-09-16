rule TTP_XOR_WriteProcessMemory_15b2 {
  strings:
    $key_15b2 = { 42 c0 [2] 70 e2 [2] 76 d7 [2] 58 d7 [2] 67 cb }

  condition:
    any of them
}