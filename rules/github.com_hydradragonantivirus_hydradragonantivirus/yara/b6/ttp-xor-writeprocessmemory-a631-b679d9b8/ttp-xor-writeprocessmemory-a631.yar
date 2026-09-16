rule TTP_XOR_WriteProcessMemory_a631 {
  strings:
    $key_a631 = { f1 43 [2] c3 61 [2] c5 54 [2] eb 54 [2] d4 48 }

  condition:
    any of them
}