rule TTP_XOR_WriteProcessMemory_a036 {
  strings:
    $key_a036 = { f7 44 [2] c5 66 [2] c3 53 [2] ed 53 [2] d2 4f }

  condition:
    any of them
}