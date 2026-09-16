rule TTP_XOR_WriteProcessMemory_a2b2 {
  strings:
    $key_a2b2 = { f5 c0 [2] c7 e2 [2] c1 d7 [2] ef d7 [2] d0 cb }

  condition:
    any of them
}