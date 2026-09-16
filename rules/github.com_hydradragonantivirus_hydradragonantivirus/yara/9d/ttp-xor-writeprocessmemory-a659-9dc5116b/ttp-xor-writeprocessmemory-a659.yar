rule TTP_XOR_WriteProcessMemory_a659 {
  strings:
    $key_a659 = { f1 2b [2] c3 09 [2] c5 3c [2] eb 3c [2] d4 20 }

  condition:
    any of them
}