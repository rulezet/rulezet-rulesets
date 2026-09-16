rule TTP_XOR_WriteProcessMemory_a2a3 {
  strings:
    $key_a2a3 = { f5 d1 [2] c7 f3 [2] c1 c6 [2] ef c6 [2] d0 da }

  condition:
    any of them
}