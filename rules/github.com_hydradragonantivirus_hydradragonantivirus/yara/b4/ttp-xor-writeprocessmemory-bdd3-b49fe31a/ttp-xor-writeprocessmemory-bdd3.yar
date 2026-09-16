rule TTP_XOR_WriteProcessMemory_bdd3 {
  strings:
    $key_bdd3 = { ea a1 [2] d8 83 [2] de b6 [2] f0 b6 [2] cf aa }

  condition:
    any of them
}