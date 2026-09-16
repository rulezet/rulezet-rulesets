rule TTP_XOR_WriteProcessMemory_a290 {
  strings:
    $key_a290 = { f5 e2 [2] c7 c0 [2] c1 f5 [2] ef f5 [2] d0 e9 }

  condition:
    any of them
}