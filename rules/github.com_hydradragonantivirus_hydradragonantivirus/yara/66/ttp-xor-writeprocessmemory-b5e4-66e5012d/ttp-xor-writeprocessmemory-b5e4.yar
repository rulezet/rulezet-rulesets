rule TTP_XOR_WriteProcessMemory_b5e4 {
  strings:
    $key_b5e4 = { e2 96 [2] d0 b4 [2] d6 81 [2] f8 81 [2] c7 9d }

  condition:
    any of them
}