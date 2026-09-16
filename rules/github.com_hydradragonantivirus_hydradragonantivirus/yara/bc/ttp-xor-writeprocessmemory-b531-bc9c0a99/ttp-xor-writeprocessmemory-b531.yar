rule TTP_XOR_WriteProcessMemory_b531 {
  strings:
    $key_b531 = { e2 43 [2] d0 61 [2] d6 54 [2] f8 54 [2] c7 48 }

  condition:
    any of them
}