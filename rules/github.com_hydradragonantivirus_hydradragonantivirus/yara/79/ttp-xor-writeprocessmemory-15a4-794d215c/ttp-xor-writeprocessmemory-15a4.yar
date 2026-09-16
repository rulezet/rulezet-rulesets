rule TTP_XOR_WriteProcessMemory_15a4 {
  strings:
    $key_15a4 = { 42 d6 [2] 70 f4 [2] 76 c1 [2] 58 c1 [2] 67 dd }

  condition:
    any of them
}