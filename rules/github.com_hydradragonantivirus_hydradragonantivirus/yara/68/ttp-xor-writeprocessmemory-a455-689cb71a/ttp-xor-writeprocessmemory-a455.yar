rule TTP_XOR_WriteProcessMemory_a455 {
  strings:
    $key_a455 = { f3 27 [2] c1 05 [2] c7 30 [2] e9 30 [2] d6 2c }

  condition:
    any of them
}