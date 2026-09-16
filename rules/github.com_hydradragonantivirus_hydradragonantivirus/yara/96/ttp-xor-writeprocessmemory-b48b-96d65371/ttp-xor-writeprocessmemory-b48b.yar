rule TTP_XOR_WriteProcessMemory_b48b {
  strings:
    $key_b48b = { e3 f9 [2] d1 db [2] d7 ee [2] f9 ee [2] c6 f2 }

  condition:
    any of them
}