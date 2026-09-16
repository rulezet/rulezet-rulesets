rule TTP_XOR_WriteProcessMemory_8885 {
  strings:
    $key_8885 = { df f7 [2] ed d5 [2] eb e0 [2] c5 e0 [2] fa fc }

  condition:
    any of them
}