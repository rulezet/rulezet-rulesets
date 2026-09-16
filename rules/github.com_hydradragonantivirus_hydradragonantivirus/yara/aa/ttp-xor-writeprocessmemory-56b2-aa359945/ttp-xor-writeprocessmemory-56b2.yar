rule TTP_XOR_WriteProcessMemory_56b2 {
  strings:
    $key_56b2 = { 01 c0 [2] 33 e2 [2] 35 d7 [2] 1b d7 [2] 24 cb }

  condition:
    any of them
}