rule TTP_XOR_WriteProcessMemory_bdd5 {
  strings:
    $key_bdd5 = { ea a7 [2] d8 85 [2] de b0 [2] f0 b0 [2] cf ac }

  condition:
    any of them
}