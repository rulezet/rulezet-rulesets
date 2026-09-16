rule TTP_XOR_WriteProcessMemory_a665 {
  strings:
    $key_a665 = { f1 17 [2] c3 35 [2] c5 00 [2] eb 00 [2] d4 1c }

  condition:
    any of them
}