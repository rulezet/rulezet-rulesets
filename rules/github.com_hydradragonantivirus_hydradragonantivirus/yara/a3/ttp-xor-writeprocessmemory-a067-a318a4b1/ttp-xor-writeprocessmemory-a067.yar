rule TTP_XOR_WriteProcessMemory_a067 {
  strings:
    $key_a067 = { f7 15 [2] c5 37 [2] c3 02 [2] ed 02 [2] d2 1e }

  condition:
    any of them
}