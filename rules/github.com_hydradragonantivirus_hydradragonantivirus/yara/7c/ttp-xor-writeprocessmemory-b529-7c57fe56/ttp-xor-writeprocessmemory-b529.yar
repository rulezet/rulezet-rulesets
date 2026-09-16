rule TTP_XOR_WriteProcessMemory_b529 {
  strings:
    $key_b529 = { e2 5b [2] d0 79 [2] d6 4c [2] f8 4c [2] c7 50 }

  condition:
    any of them
}