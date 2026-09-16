rule TTP_XOR_WriteProcessMemory_b4e9 {
  strings:
    $key_b4e9 = { e3 9b [2] d1 b9 [2] d7 8c [2] f9 8c [2] c6 90 }

  condition:
    any of them
}