rule TTP_XOR_WriteProcessMemory_a629 {
  strings:
    $key_a629 = { f1 5b [2] c3 79 [2] c5 4c [2] eb 4c [2] d4 50 }

  condition:
    any of them
}