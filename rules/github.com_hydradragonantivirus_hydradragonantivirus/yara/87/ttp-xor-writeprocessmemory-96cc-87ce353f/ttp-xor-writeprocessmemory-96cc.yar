rule TTP_XOR_WriteProcessMemory_96cc {
  strings:
    $key_96cc = { c1 be [2] f3 9c [2] f5 a9 [2] db a9 [2] e4 b5 }

  condition:
    any of them
}