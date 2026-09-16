rule TTP_XOR_WriteProcessMemory_87d7 {
  strings:
    $key_87d7 = { d0 a5 [2] e2 87 [2] e4 b2 [2] ca b2 [2] f5 ae }

  condition:
    any of them
}