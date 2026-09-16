rule TTP_XOR_WriteProcessMemory_a033 {
  strings:
    $key_a033 = { f7 41 [2] c5 63 [2] c3 56 [2] ed 56 [2] d2 4a }

  condition:
    any of them
}