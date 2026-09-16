rule TTP_XOR_WriteProcessMemory_0783 {
  strings:
    $key_0783 = { 50 f1 [2] 62 d3 [2] 64 e6 [2] 4a e6 [2] 75 fa }

  condition:
    any of them
}