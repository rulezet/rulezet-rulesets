rule TTP_XOR_WriteProcessMemory_a611 {
  strings:
    $key_a611 = { f1 63 [2] c3 41 [2] c5 74 [2] eb 74 [2] d4 68 }

  condition:
    any of them
}