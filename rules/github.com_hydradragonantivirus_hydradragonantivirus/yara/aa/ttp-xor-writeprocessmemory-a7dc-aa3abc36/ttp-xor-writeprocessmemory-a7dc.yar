rule TTP_XOR_WriteProcessMemory_a7dc {
  strings:
    $key_a7dc = { f0 ae [2] c2 8c [2] c4 b9 [2] ea b9 [2] d5 a5 }

  condition:
    any of them
}