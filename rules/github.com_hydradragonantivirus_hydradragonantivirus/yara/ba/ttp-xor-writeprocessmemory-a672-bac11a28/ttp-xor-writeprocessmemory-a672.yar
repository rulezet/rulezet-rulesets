rule TTP_XOR_WriteProcessMemory_a672 {
  strings:
    $key_a672 = { f1 00 [2] c3 22 [2] c5 17 [2] eb 17 [2] d4 0b }

  condition:
    any of them
}