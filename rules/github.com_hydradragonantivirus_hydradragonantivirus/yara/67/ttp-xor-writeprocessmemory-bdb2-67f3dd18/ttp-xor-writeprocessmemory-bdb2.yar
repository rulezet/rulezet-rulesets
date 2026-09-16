rule TTP_XOR_WriteProcessMemory_bdb2 {
  strings:
    $key_bdb2 = { ea c0 [2] d8 e2 [2] de d7 [2] f0 d7 [2] cf cb }

  condition:
    any of them
}