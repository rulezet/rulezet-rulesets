rule TTP_XOR_WriteProcessMemory_b5f9 {
  strings:
    $key_b5f9 = { e2 8b [2] d0 a9 [2] d6 9c [2] f8 9c [2] c7 80 }

  condition:
    any of them
}