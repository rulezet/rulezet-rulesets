rule TTP_XOR_WriteProcessMemory_8ed7 {
  strings:
    $key_8ed7 = { d9 a5 [2] eb 87 [2] ed b2 [2] c3 b2 [2] fc ae }

  condition:
    any of them
}