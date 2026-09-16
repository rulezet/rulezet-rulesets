rule TTP_XOR_WriteProcessMemory_ac83 {
  strings:
    $key_ac83 = { fb f1 [2] c9 d3 [2] cf e6 [2] e1 e6 [2] de fa }

  condition:
    any of them
}