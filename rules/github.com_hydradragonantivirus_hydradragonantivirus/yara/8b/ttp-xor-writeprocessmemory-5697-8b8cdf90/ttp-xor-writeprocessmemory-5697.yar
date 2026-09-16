rule TTP_XOR_WriteProcessMemory_5697 {
  strings:
    $key_5697 = { 01 e5 [2] 33 c7 [2] 35 f2 [2] 1b f2 [2] 24 ee }

  condition:
    any of them
}