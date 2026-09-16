rule TTP_XOR_WriteProcessMemory_a0c3 {
  strings:
    $key_a0c3 = { f7 b1 [2] c5 93 [2] c3 a6 [2] ed a6 [2] d2 ba }

  condition:
    any of them
}