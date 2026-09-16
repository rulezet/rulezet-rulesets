rule TTP_XOR_WriteProcessMemory_60b2 {
  strings:
    $key_60b2 = { 37 c0 [2] 05 e2 [2] 03 d7 [2] 2d d7 [2] 12 cb }

  condition:
    any of them
}