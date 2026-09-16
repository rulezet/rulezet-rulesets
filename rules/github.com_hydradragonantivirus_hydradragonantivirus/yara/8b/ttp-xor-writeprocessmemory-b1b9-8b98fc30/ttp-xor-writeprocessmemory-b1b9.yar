rule TTP_XOR_WriteProcessMemory_b1b9 {
  strings:
    $key_b1b9 = { e6 cb [2] d4 e9 [2] d2 dc [2] fc dc [2] c3 c0 }

  condition:
    any of them
}