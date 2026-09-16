rule TTP_XOR_WriteProcessMemory_fbb4 {
  strings:
    $key_fbb4 = { ac c6 [2] 9e e4 [2] 98 d1 [2] b6 d1 [2] 89 cd }

  condition:
    any of them
}