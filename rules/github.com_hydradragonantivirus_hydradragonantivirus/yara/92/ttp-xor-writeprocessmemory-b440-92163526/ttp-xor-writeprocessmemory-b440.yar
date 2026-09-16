rule TTP_XOR_WriteProcessMemory_b440 {
  strings:
    $key_b440 = { e3 32 [2] d1 10 [2] d7 25 [2] f9 25 [2] c6 39 }

  condition:
    any of them
}