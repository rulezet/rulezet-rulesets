rule TTP_XOR_WriteProcessMemory_bb61 {
  strings:
    $key_bb61 = { ec 13 [2] de 31 [2] d8 04 [2] f6 04 [2] c9 18 }

  condition:
    any of them
}