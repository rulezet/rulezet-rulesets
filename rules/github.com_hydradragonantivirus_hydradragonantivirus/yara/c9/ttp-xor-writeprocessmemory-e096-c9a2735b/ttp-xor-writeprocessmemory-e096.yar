rule TTP_XOR_WriteProcessMemory_e096 {
  strings:
    $key_e096 = { b7 e4 [2] 85 c6 [2] 83 f3 [2] ad f3 [2] 92 ef }

  condition:
    any of them
}