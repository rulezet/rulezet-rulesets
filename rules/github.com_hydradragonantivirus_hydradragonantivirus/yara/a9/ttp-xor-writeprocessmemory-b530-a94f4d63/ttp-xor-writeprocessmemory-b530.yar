rule TTP_XOR_WriteProcessMemory_b530 {
  strings:
    $key_b530 = { e2 42 [2] d0 60 [2] d6 55 [2] f8 55 [2] c7 49 }

  condition:
    any of them
}