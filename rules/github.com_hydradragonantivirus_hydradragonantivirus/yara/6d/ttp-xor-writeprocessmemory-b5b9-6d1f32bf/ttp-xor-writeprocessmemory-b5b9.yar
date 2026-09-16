rule TTP_XOR_WriteProcessMemory_b5b9 {
  strings:
    $key_b5b9 = { e2 cb [2] d0 e9 [2] d6 dc [2] f8 dc [2] c7 c0 }

  condition:
    any of them
}