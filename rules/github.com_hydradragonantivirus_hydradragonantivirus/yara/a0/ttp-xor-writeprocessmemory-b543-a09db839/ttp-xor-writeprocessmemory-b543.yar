rule TTP_XOR_WriteProcessMemory_b543 {
  strings:
    $key_b543 = { e2 31 [2] d0 13 [2] d6 26 [2] f8 26 [2] c7 3a }

  condition:
    any of them
}