rule TTP_XOR_WriteProcessMemory_a480 {
  strings:
    $key_a480 = { f3 f2 [2] c1 d0 [2] c7 e5 [2] e9 e5 [2] d6 f9 }

  condition:
    any of them
}