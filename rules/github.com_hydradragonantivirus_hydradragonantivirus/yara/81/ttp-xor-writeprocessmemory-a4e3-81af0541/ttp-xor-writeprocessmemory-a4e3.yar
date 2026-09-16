rule TTP_XOR_WriteProcessMemory_a4e3 {
  strings:
    $key_a4e3 = { f3 91 [2] c1 b3 [2] c7 86 [2] e9 86 [2] d6 9a }

  condition:
    any of them
}