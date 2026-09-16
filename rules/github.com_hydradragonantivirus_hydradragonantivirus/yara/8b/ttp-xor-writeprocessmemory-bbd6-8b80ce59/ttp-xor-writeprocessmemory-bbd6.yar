rule TTP_XOR_WriteProcessMemory_bbd6 {
  strings:
    $key_bbd6 = { ec a4 [2] de 86 [2] d8 b3 [2] f6 b3 [2] c9 af }

  condition:
    any of them
}