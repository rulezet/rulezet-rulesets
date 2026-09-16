rule TTP_XOR_WriteProcessMemory_bb85 {
  strings:
    $key_bb85 = { ec f7 [2] de d5 [2] d8 e0 [2] f6 e0 [2] c9 fc }

  condition:
    any of them
}