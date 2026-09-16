rule TTP_XOR_WriteProcessMemory_93b3 {
  strings:
    $key_93b3 = { c4 c1 [2] f6 e3 [2] f0 d6 [2] de d6 [2] e1 ca }

  condition:
    any of them
}