rule TTP_XOR_WriteProcessMemory_b470 {
  strings:
    $key_b470 = { e3 02 [2] d1 20 [2] d7 15 [2] f9 15 [2] c6 09 }

  condition:
    any of them
}