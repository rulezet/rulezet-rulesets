rule TTP_XOR_WriteProcessMemory_93c3 {
  strings:
    $key_93c3 = { c4 b1 [2] f6 93 [2] f0 a6 [2] de a6 [2] e1 ba }

  condition:
    any of them
}