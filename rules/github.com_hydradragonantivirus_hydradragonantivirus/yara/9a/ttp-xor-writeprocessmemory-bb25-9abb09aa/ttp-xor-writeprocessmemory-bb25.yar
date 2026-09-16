rule TTP_XOR_WriteProcessMemory_bb25 {
  strings:
    $key_bb25 = { ec 57 [2] de 75 [2] d8 40 [2] f6 40 [2] c9 5c }

  condition:
    any of them
}