rule TTP_XOR_WriteProcessMemory_e583 {
  strings:
    $key_e583 = { b2 f1 [2] 80 d3 [2] 86 e6 [2] a8 e6 [2] 97 fa }

  condition:
    any of them
}