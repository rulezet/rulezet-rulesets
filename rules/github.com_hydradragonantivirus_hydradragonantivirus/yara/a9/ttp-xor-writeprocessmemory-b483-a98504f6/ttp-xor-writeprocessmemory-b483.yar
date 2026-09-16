rule TTP_XOR_WriteProcessMemory_b483 {
  strings:
    $key_b483 = { e3 f1 [2] d1 d3 [2] d7 e6 [2] f9 e6 [2] c6 fa }

  condition:
    any of them
}