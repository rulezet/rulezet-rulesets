rule TTP_XOR_WriteProcessMemory_a3b2 {
  strings:
    $key_a3b2 = { f4 c0 [2] c6 e2 [2] c0 d7 [2] ee d7 [2] d1 cb }

  condition:
    any of them
}