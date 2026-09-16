rule TTP_XOR_WriteProcessMemory_bb06 {
  strings:
    $key_bb06 = { ec 74 [2] de 56 [2] d8 63 [2] f6 63 [2] c9 7f }

  condition:
    any of them
}