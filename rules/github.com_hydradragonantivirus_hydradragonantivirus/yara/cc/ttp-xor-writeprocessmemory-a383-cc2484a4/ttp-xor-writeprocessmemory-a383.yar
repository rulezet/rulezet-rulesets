rule TTP_XOR_WriteProcessMemory_a383 {
  strings:
    $key_a383 = { f4 f1 [2] c6 d3 [2] c0 e6 [2] ee e6 [2] d1 fa }

  condition:
    any of them
}