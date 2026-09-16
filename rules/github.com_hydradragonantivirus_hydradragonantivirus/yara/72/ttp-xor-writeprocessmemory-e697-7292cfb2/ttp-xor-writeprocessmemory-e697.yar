rule TTP_XOR_WriteProcessMemory_e697 {
  strings:
    $key_e697 = { b1 e5 [2] 83 c7 [2] 85 f2 [2] ab f2 [2] 94 ee }

  condition:
    any of them
}