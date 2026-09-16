rule TTP_XOR_WriteProcessMemory_a074 {
  strings:
    $key_a074 = { f7 06 [2] c5 24 [2] c3 11 [2] ed 11 [2] d2 0d }

  condition:
    any of them
}