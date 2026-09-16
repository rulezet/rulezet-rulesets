rule TTP_XOR_WriteProcessMemory_6383 {
  strings:
    $key_6383 = { 34 f1 [2] 06 d3 [2] 00 e6 [2] 2e e6 [2] 11 fa }

  condition:
    any of them
}