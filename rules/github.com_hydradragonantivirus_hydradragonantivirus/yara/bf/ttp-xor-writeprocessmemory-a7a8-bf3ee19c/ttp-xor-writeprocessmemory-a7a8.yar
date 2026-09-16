rule TTP_XOR_WriteProcessMemory_a7a8 {
  strings:
    $key_a7a8 = { f0 da [2] c2 f8 [2] c4 cd [2] ea cd [2] d5 d1 }

  condition:
    any of them
}