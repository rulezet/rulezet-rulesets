rule TTP_XOR_WriteProcessMemory_ac77 {
  strings:
    $key_ac77 = { fb 05 [2] c9 27 [2] cf 12 [2] e1 12 [2] de 0e }

  condition:
    any of them
}