rule TTP_XOR_WriteProcessMemory_33a4 {
  strings:
    $key_33a4 = { 64 d6 [2] 56 f4 [2] 50 c1 [2] 7e c1 [2] 41 dd }

  condition:
    any of them
}