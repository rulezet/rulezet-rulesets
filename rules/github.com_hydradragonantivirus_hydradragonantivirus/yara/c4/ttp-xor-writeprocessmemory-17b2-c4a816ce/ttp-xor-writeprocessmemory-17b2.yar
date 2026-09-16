rule TTP_XOR_WriteProcessMemory_17b2 {
  strings:
    $key_17b2 = { 40 c0 [2] 72 e2 [2] 74 d7 [2] 5a d7 [2] 65 cb }

  condition:
    any of them
}