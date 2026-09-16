rule TTP_XOR_WriteProcessMemory_e283 {
  strings:
    $key_e283 = { b5 f1 [2] 87 d3 [2] 81 e6 [2] af e6 [2] 90 fa }

  condition:
    any of them
}