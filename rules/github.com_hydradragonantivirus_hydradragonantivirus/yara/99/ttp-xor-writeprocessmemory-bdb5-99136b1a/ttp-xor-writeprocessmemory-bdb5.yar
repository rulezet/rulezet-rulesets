rule TTP_XOR_WriteProcessMemory_bdb5 {
  strings:
    $key_bdb5 = { ea c7 [2] d8 e5 [2] de d0 [2] f0 d0 [2] cf cc }

  condition:
    any of them
}