rule TTP_XOR_WriteProcessMemory_a639 {
  strings:
    $key_a639 = { f1 4b [2] c3 69 [2] c5 5c [2] eb 5c [2] d4 40 }

  condition:
    any of them
}