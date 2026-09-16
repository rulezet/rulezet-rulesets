rule TTP_XOR_WriteProcessMemory_f583 {
  strings:
    $key_f583 = { a2 f1 [2] 90 d3 [2] 96 e6 [2] b8 e6 [2] 87 fa }

  condition:
    any of them
}