rule TTP_XOR_WriteProcessMemory_1683 {
  strings:
    $key_1683 = { 41 f1 [2] 73 d3 [2] 75 e6 [2] 5b e6 [2] 64 fa }

  condition:
    any of them
}