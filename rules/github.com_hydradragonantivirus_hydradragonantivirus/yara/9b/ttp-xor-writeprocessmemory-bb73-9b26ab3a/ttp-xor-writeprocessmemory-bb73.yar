rule TTP_XOR_WriteProcessMemory_bb73 {
  strings:
    $key_bb73 = { ec 01 [2] de 23 [2] d8 16 [2] f6 16 [2] c9 0a }

  condition:
    any of them
}