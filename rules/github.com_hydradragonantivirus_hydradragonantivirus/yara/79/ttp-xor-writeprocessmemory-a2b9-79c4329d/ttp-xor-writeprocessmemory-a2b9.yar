rule TTP_XOR_WriteProcessMemory_a2b9 {
  strings:
    $key_a2b9 = { f5 cb [2] c7 e9 [2] c1 dc [2] ef dc [2] d0 c0 }

  condition:
    any of them
}