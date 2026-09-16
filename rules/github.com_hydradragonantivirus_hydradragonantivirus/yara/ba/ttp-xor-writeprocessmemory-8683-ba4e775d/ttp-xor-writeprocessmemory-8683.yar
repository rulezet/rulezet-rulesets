rule TTP_XOR_WriteProcessMemory_8683 {
  strings:
    $key_8683 = { d1 f1 [2] e3 d3 [2] e5 e6 [2] cb e6 [2] f4 fa }

  condition:
    any of them
}