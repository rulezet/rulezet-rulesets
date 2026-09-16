rule TTP_XOR_WriteProcessMemory_bbd2 {
  strings:
    $key_bbd2 = { ec a0 [2] de 82 [2] d8 b7 [2] f6 b7 [2] c9 ab }

  condition:
    any of them
}