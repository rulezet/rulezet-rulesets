rule TTP_XOR_WriteProcessMemory_94cc {
  strings:
    $key_94cc = { c3 be [2] f1 9c [2] f7 a9 [2] d9 a9 [2] e6 b5 }

  condition:
    any of them
}