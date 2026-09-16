rule TTP_XOR_WriteProcessMemory_a4f4 {
  strings:
    $key_a4f4 = { f3 86 [2] c1 a4 [2] c7 91 [2] e9 91 [2] d6 8d }

  condition:
    any of them
}