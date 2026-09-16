rule TTP_XOR_WriteProcessMemory_b553 {
  strings:
    $key_b553 = { e2 21 [2] d0 03 [2] d6 36 [2] f8 36 [2] c7 2a }

  condition:
    any of them
}