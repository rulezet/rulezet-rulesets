rule TTP_XOR_WriteProcessMemory_b434 {
  strings:
    $key_b434 = { e3 46 [2] d1 64 [2] d7 51 [2] f9 51 [2] c6 4d }

  condition:
    any of them
}