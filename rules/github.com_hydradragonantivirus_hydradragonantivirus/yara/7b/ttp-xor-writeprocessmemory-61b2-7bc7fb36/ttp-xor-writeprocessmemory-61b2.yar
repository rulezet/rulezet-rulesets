rule TTP_XOR_WriteProcessMemory_61b2 {
  strings:
    $key_61b2 = { 36 c0 [2] 04 e2 [2] 02 d7 [2] 2c d7 [2] 13 cb }

  condition:
    any of them
}