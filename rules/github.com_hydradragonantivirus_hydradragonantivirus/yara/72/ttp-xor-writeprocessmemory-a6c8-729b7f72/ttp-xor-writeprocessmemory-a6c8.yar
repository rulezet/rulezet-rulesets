rule TTP_XOR_WriteProcessMemory_a6c8 {
  strings:
    $key_a6c8 = { f1 ba [2] c3 98 [2] c5 ad [2] eb ad [2] d4 b1 }

  condition:
    any of them
}