rule TTP_XOR_WriteProcessMemory_5483 {
  strings:
    $key_5483 = { 03 f1 [2] 31 d3 [2] 37 e6 [2] 19 e6 [2] 26 fa }

  condition:
    any of them
}