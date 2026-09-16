rule TTP_XOR_WriteProcessMemory_e0a4 {
  strings:
    $key_e0a4 = { b7 d6 [2] 85 f4 [2] 83 c1 [2] ad c1 [2] 92 dd }

  condition:
    any of them
}