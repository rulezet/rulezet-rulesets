rule TTP_XOR_WriteProcessMemory_e285 {
  strings:
    $key_e285 = { b5 f7 [2] 87 d5 [2] 81 e0 [2] af e0 [2] 90 fc }

  condition:
    any of them
}