rule TTP_XOR_WriteProcessMemory_13a4 {
  strings:
    $key_13a4 = { 44 d6 [2] 76 f4 [2] 70 c1 [2] 5e c1 [2] 61 dd }

  condition:
    any of them
}