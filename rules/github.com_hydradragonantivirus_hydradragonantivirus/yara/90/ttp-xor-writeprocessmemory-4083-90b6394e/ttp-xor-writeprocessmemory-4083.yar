rule TTP_XOR_WriteProcessMemory_4083 {
  strings:
    $key_4083 = { 17 f1 [2] 25 d3 [2] 23 e6 [2] 0d e6 [2] 32 fa }

  condition:
    any of them
}