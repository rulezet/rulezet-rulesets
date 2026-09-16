rule TTP_XOR_WriteProcessMemory_1083 {
  strings:
    $key_1083 = { 47 f1 [2] 75 d3 [2] 73 e6 [2] 5d e6 [2] 62 fa }

  condition:
    any of them
}