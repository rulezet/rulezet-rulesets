rule TTP_XOR_WriteProcessMemory_02b2 {
  strings:
    $key_02b2 = { 55 c0 [2] 67 e2 [2] 61 d7 [2] 4f d7 [2] 70 cb }

  condition:
    any of them
}