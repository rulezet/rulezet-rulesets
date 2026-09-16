rule TTP_XOR_WriteProcessMemory_84cc {
  strings:
    $key_84cc = { d3 be [2] e1 9c [2] e7 a9 [2] c9 a9 [2] f6 b5 }

  condition:
    any of them
}