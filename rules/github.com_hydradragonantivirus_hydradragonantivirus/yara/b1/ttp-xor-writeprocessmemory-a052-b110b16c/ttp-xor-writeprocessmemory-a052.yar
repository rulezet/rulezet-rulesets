rule TTP_XOR_WriteProcessMemory_a052 {
  strings:
    $key_a052 = { f7 20 [2] c5 02 [2] c3 37 [2] ed 37 [2] d2 2b }

  condition:
    any of them
}