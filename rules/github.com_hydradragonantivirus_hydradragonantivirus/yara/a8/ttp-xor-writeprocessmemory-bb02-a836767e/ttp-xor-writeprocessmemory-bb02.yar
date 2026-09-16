rule TTP_XOR_WriteProcessMemory_bb02 {
  strings:
    $key_bb02 = { ec 70 [2] de 52 [2] d8 67 [2] f6 67 [2] c9 7b }

  condition:
    any of them
}