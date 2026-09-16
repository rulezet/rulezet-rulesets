rule TTP_XOR_WriteProcessMemory_82cc {
  strings:
    $key_82cc = { d5 be [2] e7 9c [2] e1 a9 [2] cf a9 [2] f0 b5 }

  condition:
    any of them
}