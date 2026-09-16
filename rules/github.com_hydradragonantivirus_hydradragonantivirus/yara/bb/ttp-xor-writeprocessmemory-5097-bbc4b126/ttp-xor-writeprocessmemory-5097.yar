rule TTP_XOR_WriteProcessMemory_5097 {
  strings:
    $key_5097 = { 07 e5 [2] 35 c7 [2] 33 f2 [2] 1d f2 [2] 22 ee }

  condition:
    any of them
}