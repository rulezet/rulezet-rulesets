rule TTP_XOR_WriteProcessMemory_bb27 {
  strings:
    $key_bb27 = { ec 55 [2] de 77 [2] d8 42 [2] f6 42 [2] c9 5e }

  condition:
    any of them
}