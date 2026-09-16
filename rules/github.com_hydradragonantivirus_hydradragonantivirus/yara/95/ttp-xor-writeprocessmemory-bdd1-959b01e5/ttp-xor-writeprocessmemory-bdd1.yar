rule TTP_XOR_WriteProcessMemory_bdd1 {
  strings:
    $key_bdd1 = { ea a3 [2] d8 81 [2] de b4 [2] f0 b4 [2] cf a8 }

  condition:
    any of them
}