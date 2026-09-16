rule TTP_XOR_WriteProcessMemory_a091 {
  strings:
    $key_a091 = { f7 e3 [2] c5 c1 [2] c3 f4 [2] ed f4 [2] d2 e8 }

  condition:
    any of them
}