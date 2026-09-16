rule TTP_XOR_WriteProcessMemory_8583 {
  strings:
    $key_8583 = { d2 f1 [2] e0 d3 [2] e6 e6 [2] c8 e6 [2] f7 fa }

  condition:
    any of them
}