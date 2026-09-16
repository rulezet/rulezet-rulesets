rule TTP_XOR_WriteProcessMemory_6497 {
  strings:
    $key_6497 = { 33 e5 [2] 01 c7 [2] 07 f2 [2] 29 f2 [2] 16 ee }

  condition:
    any of them
}