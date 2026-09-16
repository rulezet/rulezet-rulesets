rule TTP_XOR_WriteProcessMemory_94c3 {
  strings:
    $key_94c3 = { c3 b1 [2] f1 93 [2] f7 a6 [2] d9 a6 [2] e6 ba }

  condition:
    any of them
}