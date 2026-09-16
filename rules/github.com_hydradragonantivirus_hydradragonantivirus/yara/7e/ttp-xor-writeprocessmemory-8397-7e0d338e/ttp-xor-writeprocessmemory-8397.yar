rule TTP_XOR_WriteProcessMemory_8397 {
  strings:
    $key_8397 = { d4 e5 [2] e6 c7 [2] e0 f2 [2] ce f2 [2] f1 ee }

  condition:
    any of them
}