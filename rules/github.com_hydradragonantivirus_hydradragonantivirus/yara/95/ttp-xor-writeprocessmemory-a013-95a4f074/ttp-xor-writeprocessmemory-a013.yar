rule TTP_XOR_WriteProcessMemory_a013 {
  strings:
    $key_a013 = { f7 61 [2] c5 43 [2] c3 76 [2] ed 76 [2] d2 6a }

  condition:
    any of them
}