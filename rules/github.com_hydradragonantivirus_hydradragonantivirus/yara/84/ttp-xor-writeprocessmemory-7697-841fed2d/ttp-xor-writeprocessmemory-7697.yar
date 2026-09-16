rule TTP_XOR_WriteProcessMemory_7697 {
  strings:
    $key_7697 = { 21 e5 [2] 13 c7 [2] 15 f2 [2] 3b f2 [2] 04 ee }

  condition:
    any of them
}