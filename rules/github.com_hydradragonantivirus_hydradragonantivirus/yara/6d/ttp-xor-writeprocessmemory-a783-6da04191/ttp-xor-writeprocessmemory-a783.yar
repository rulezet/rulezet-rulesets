rule TTP_XOR_WriteProcessMemory_a783 {
  strings:
    $key_a783 = { f0 f1 [2] c2 d3 [2] c4 e6 [2] ea e6 [2] d5 fa }

  condition:
    any of them
}