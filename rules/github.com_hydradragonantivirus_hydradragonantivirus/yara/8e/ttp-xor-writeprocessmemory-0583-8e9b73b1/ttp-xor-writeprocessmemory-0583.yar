rule TTP_XOR_WriteProcessMemory_0583 {
  strings:
    $key_0583 = { 52 f1 [2] 60 d3 [2] 66 e6 [2] 48 e6 [2] 77 fa }

  condition:
    any of them
}