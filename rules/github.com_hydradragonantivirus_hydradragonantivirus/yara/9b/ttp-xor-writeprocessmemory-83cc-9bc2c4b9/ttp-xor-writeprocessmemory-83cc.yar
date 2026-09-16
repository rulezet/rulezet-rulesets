rule TTP_XOR_WriteProcessMemory_83cc {
  strings:
    $key_83cc = { d4 be [2] e6 9c [2] e0 a9 [2] ce a9 [2] f1 b5 }

  condition:
    any of them
}