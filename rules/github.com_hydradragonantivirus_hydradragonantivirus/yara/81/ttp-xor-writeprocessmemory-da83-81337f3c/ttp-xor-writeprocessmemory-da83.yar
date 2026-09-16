rule TTP_XOR_WriteProcessMemory_da83 {
  strings:
    $key_da83 = { 8d f1 [2] bf d3 [2] b9 e6 [2] 97 e6 [2] a8 fa }

  condition:
    any of them
}