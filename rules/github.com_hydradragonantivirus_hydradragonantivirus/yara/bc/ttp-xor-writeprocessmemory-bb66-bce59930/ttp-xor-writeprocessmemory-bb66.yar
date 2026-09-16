rule TTP_XOR_WriteProcessMemory_bb66 {
  strings:
    $key_bb66 = { ec 14 [2] de 36 [2] d8 03 [2] f6 03 [2] c9 1f }

  condition:
    any of them
}