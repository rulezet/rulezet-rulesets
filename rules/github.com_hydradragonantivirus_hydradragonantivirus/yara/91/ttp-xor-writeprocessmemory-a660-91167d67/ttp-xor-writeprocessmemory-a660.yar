rule TTP_XOR_WriteProcessMemory_a660 {
  strings:
    $key_a660 = { f1 12 [2] c3 30 [2] c5 05 [2] eb 05 [2] d4 19 }

  condition:
    any of them
}