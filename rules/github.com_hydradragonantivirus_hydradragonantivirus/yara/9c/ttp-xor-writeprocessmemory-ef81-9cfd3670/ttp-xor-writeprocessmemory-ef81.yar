rule TTP_XOR_WriteProcessMemory_ef81 {
  strings:
    $key_ef81 = { b8 f3 [2] 8a d1 [2] 8c e4 [2] a2 e4 [2] 9d f8 }

  condition:
    any of them
}