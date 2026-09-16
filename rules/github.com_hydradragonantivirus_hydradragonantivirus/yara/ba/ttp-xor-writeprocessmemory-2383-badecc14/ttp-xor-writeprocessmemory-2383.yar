rule TTP_XOR_WriteProcessMemory_2383 {
  strings:
    $key_2383 = { 74 f1 [2] 46 d3 [2] 40 e6 [2] 6e e6 [2] 51 fa }

  condition:
    any of them
}