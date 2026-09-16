rule TTP_XOR_WriteProcessMemory_bca4 {
  strings:
    $key_bca4 = { eb d6 [2] d9 f4 [2] df c1 [2] f1 c1 [2] ce dd }

  condition:
    any of them
}