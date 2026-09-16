rule TTP_XOR_WriteProcessMemory_a652 {
  strings:
    $key_a652 = { f1 20 [2] c3 02 [2] c5 37 [2] eb 37 [2] d4 2b }

  condition:
    any of them
}