rule TTP_XOR_WriteProcessMemory_a1cc {
  strings:
    $key_a1cc = { f6 be [2] c4 9c [2] c2 a9 [2] ec a9 [2] d3 b5 }

  condition:
    any of them
}