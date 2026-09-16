rule TTP_XOR_WriteProcessMemory_19b4 {
  strings:
    $key_19b4 = { 4e c6 [2] 7c e4 [2] 7a d1 [2] 54 d1 [2] 6b cd }

  condition:
    any of them
}