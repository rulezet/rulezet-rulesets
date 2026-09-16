rule TTP_XOR_WriteProcessMemory_b5e9 {
  strings:
    $key_b5e9 = { e2 9b [2] d0 b9 [2] d6 8c [2] f8 8c [2] c7 90 }

  condition:
    any of them
}