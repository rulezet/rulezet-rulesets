rule TTP_XOR_WriteProcessMemory_a0b3 {
  strings:
    $key_a0b3 = { f7 c1 [2] c5 e3 [2] c3 d6 [2] ed d6 [2] d2 ca }

  condition:
    any of them
}