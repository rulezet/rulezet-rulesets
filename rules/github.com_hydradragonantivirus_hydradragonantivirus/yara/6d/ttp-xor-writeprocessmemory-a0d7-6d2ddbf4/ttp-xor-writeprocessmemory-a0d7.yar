rule TTP_XOR_WriteProcessMemory_a0d7 {
  strings:
    $key_a0d7 = { f7 a5 [2] c5 87 [2] c3 b2 [2] ed b2 [2] d2 ae }

  condition:
    any of them
}