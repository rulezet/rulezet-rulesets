rule TTP_XOR_WriteProcessMemory_a094 {
  strings:
    $key_a094 = { f7 e6 [2] c5 c4 [2] c3 f1 [2] ed f1 [2] d2 ed }

  condition:
    any of them
}