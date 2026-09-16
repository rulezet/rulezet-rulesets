rule TTP_XOR_WriteProcessMemory_fbb1 {
  strings:
    $key_fbb1 = { ac c3 [2] 9e e1 [2] 98 d4 [2] b6 d4 [2] 89 c8 }

  condition:
    any of them
}