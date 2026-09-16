rule TTP_XOR_WriteProcessMemory_a697 {
  strings:
    $key_a697 = { f1 e5 [2] c3 c7 [2] c5 f2 [2] eb f2 [2] d4 ee }

  condition:
    any of them
}