rule TTP_XOR_WriteProcessMemory_75b2 {
  strings:
    $key_75b2 = { 22 c0 [2] 10 e2 [2] 16 d7 [2] 38 d7 [2] 07 cb }

  condition:
    any of them
}