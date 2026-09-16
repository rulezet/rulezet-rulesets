rule TTP_XOR_WriteProcessMemory_bd84 {
  strings:
    $key_bd84 = { ea f6 [2] d8 d4 [2] de e1 [2] f0 e1 [2] cf fd }

  condition:
    any of them
}