rule TTP_XOR_WriteProcessMemory_bb95 {
  strings:
    $key_bb95 = { ec e7 [2] de c5 [2] d8 f0 [2] f6 f0 [2] c9 ec }

  condition:
    any of them
}