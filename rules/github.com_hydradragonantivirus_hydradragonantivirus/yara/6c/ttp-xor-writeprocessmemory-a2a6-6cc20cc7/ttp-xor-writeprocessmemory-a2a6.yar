rule TTP_XOR_WriteProcessMemory_a2a6 {
  strings:
    $key_a2a6 = { f5 d4 [2] c7 f6 [2] c1 c3 [2] ef c3 [2] d0 df }

  condition:
    any of them
}