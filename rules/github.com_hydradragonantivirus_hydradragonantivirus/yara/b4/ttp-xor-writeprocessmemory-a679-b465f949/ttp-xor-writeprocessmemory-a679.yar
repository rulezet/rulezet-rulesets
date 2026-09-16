rule TTP_XOR_WriteProcessMemory_a679 {
  strings:
    $key_a679 = { f1 0b [2] c3 29 [2] c5 1c [2] eb 1c [2] d4 00 }

  condition:
    any of them
}