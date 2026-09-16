rule TTP_XOR_WriteProcessMemory_a030 {
  strings:
    $key_a030 = { f7 42 [2] c5 60 [2] c3 55 [2] ed 55 [2] d2 49 }

  condition:
    any of them
}