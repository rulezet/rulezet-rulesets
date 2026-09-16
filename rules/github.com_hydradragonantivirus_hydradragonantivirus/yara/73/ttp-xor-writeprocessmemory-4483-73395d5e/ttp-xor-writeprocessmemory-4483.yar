rule TTP_XOR_WriteProcessMemory_4483 {
  strings:
    $key_4483 = { 13 f1 [2] 21 d3 [2] 27 e6 [2] 09 e6 [2] 36 fa }

  condition:
    any of them
}