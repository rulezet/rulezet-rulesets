rule TTP_XOR_WriteProcessMemory_40b2 {
  strings:
    $key_40b2 = { 17 c0 [2] 25 e2 [2] 23 d7 [2] 0d d7 [2] 32 cb }

  condition:
    any of them
}