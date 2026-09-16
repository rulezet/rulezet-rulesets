rule TTP_XOR_WriteProcessMemory_2783 {
  strings:
    $key_2783 = { 70 f1 [2] 42 d3 [2] 44 e6 [2] 6a e6 [2] 55 fa }

  condition:
    any of them
}