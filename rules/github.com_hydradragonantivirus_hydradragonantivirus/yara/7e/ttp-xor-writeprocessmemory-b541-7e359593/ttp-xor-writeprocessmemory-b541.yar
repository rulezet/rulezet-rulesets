rule TTP_XOR_WriteProcessMemory_b541 {
  strings:
    $key_b541 = { e2 33 [2] d0 11 [2] d6 24 [2] f8 24 [2] c7 38 }

  condition:
    any of them
}