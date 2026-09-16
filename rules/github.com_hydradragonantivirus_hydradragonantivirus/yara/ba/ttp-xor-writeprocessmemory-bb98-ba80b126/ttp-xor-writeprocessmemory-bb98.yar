rule TTP_XOR_WriteProcessMemory_bb98 {
  strings:
    $key_bb98 = { ec ea [2] de c8 [2] d8 fd [2] f6 fd [2] c9 e1 }

  condition:
    any of them
}