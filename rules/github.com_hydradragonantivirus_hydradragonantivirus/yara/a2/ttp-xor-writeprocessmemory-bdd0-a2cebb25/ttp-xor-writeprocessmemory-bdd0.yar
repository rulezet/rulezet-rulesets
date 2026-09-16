rule TTP_XOR_WriteProcessMemory_bdd0 {
  strings:
    $key_bdd0 = { ea a2 [2] d8 80 [2] de b5 [2] f0 b5 [2] cf a9 }

  condition:
    any of them
}