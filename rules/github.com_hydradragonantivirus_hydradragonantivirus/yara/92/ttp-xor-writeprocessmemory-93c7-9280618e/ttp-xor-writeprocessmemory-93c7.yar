rule TTP_XOR_WriteProcessMemory_93c7 {
  strings:
    $key_93c7 = { c4 b5 [2] f6 97 [2] f0 a2 [2] de a2 [2] e1 be }

  condition:
    any of them
}