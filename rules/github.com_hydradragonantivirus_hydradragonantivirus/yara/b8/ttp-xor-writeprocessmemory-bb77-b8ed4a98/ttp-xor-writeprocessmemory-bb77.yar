rule TTP_XOR_WriteProcessMemory_bb77 {
  strings:
    $key_bb77 = { ec 05 [2] de 27 [2] d8 12 [2] f6 12 [2] c9 0e }

  condition:
    any of them
}