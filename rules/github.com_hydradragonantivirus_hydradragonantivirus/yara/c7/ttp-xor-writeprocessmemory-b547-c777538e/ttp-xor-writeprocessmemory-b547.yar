rule TTP_XOR_WriteProcessMemory_b547 {
  strings:
    $key_b547 = { e2 35 [2] d0 17 [2] d6 22 [2] f8 22 [2] c7 3e }

  condition:
    any of them
}