rule TTP_XOR_WriteProcessMemory_4697 {
  strings:
    $key_4697 = { 11 e5 [2] 23 c7 [2] 25 f2 [2] 0b f2 [2] 34 ee }

  condition:
    any of them
}