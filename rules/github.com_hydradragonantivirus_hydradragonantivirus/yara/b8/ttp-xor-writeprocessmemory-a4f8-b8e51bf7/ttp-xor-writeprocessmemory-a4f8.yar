rule TTP_XOR_WriteProcessMemory_a4f8 {
  strings:
    $key_a4f8 = { f3 8a [2] c1 a8 [2] c7 9d [2] e9 9d [2] d6 81 }

  condition:
    any of them
}