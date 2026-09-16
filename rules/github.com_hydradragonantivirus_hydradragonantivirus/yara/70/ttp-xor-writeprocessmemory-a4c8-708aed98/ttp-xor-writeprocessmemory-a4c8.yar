rule TTP_XOR_WriteProcessMemory_a4c8 {
  strings:
    $key_a4c8 = { f3 ba [2] c1 98 [2] c7 ad [2] e9 ad [2] d6 b1 }

  condition:
    any of them
}