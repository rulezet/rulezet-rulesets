rule TTP_XOR_WriteProcessMemory_40a4 {
  strings:
    $key_40a4 = { 17 d6 [2] 25 f4 [2] 23 c1 [2] 0d c1 [2] 32 dd }

  condition:
    any of them
}