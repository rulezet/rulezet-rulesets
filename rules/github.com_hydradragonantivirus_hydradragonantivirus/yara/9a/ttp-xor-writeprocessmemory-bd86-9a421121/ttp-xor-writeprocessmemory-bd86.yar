rule TTP_XOR_WriteProcessMemory_bd86 {
  strings:
    $key_bd86 = { ea f4 [2] d8 d6 [2] de e3 [2] f0 e3 [2] cf ff }

  condition:
    any of them
}