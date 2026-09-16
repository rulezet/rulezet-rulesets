rule TTP_XOR_WriteProcessMemory_a430 {
  strings:
    $key_a430 = { f3 42 [2] c1 60 [2] c7 55 [2] e9 55 [2] d6 49 }

  condition:
    any of them
}