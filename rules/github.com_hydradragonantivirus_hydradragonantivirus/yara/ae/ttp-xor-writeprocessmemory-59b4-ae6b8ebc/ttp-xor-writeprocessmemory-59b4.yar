rule TTP_XOR_WriteProcessMemory_59b4 {
  strings:
    $key_59b4 = { 0e c6 [2] 3c e4 [2] 3a d1 [2] 14 d1 [2] 2b cd }

  condition:
    any of them
}