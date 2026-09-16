rule TTP_XOR_WriteProcessMemory_b7b9 {
  strings:
    $key_b7b9 = { e0 cb [2] d2 e9 [2] d4 dc [2] fa dc [2] c5 c0 }

  condition:
    any of them
}