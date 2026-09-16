rule TTP_XOR_WriteProcessMemory_b4b9 {
  strings:
    $key_b4b9 = { e3 cb [2] d1 e9 [2] d7 dc [2] f9 dc [2] c6 c0 }

  condition:
    any of them
}