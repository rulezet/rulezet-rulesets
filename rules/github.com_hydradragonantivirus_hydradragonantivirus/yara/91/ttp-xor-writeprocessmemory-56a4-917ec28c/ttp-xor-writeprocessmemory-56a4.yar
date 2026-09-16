rule TTP_XOR_WriteProcessMemory_56a4 {
  strings:
    $key_56a4 = { 01 d6 [2] 33 f4 [2] 35 c1 [2] 1b c1 [2] 24 dd }

  condition:
    any of them
}