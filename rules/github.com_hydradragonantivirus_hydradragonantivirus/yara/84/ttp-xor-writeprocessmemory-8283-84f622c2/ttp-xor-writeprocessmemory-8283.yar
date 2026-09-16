rule TTP_XOR_WriteProcessMemory_8283 {
  strings:
    $key_8283 = { d5 f1 [2] e7 d3 [2] e1 e6 [2] cf e6 [2] f0 fa }

  condition:
    any of them
}