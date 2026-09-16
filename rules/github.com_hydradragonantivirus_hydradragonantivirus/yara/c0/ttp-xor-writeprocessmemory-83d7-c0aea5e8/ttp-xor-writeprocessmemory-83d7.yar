rule TTP_XOR_WriteProcessMemory_83d7 {
  strings:
    $key_83d7 = { d4 a5 [2] e6 87 [2] e0 b2 [2] ce b2 [2] f1 ae }

  condition:
    any of them
}