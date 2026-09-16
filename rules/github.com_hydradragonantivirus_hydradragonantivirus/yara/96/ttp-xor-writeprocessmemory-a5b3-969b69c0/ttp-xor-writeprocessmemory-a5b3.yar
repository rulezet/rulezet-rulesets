rule TTP_XOR_WriteProcessMemory_a5b3 {
  strings:
    $key_a5b3 = { f2 c1 [2] c0 e3 [2] c6 d6 [2] e8 d6 [2] d7 ca }

  condition:
    any of them
}