rule TTP_XOR_WriteProcessMemory_a683 {
  strings:
    $key_a683 = { f1 f1 [2] c3 d3 [2] c5 e6 [2] eb e6 [2] d4 fa }

  condition:
    any of them
}