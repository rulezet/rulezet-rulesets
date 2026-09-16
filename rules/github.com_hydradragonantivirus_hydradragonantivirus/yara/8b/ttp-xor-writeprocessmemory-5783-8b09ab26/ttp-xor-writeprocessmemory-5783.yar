rule TTP_XOR_WriteProcessMemory_5783 {
  strings:
    $key_5783 = { 00 f1 [2] 32 d3 [2] 34 e6 [2] 1a e6 [2] 25 fa }

  condition:
    any of them
}