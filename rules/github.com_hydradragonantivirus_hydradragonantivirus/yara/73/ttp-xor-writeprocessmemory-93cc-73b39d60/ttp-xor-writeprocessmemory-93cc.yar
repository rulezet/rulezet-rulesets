rule TTP_XOR_WriteProcessMemory_93cc {
  strings:
    $key_93cc = { c4 be [2] f6 9c [2] f0 a9 [2] de a9 [2] e1 b5 }

  condition:
    any of them
}