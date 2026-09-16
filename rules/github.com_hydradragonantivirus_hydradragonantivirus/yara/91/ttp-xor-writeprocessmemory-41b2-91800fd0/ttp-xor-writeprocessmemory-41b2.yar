rule TTP_XOR_WriteProcessMemory_41b2 {
  strings:
    $key_41b2 = { 16 c0 [2] 24 e2 [2] 22 d7 [2] 0c d7 [2] 33 cb }

  condition:
    any of them
}