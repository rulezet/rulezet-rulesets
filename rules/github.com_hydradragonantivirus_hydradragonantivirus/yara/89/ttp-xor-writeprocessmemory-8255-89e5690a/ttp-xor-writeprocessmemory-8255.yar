rule TTP_XOR_WriteProcessMemory_8255 {
  strings:
    $key_8255 = { d5 27 [2] e7 05 [2] e1 30 [2] cf 30 [2] f0 2c }

  condition:
    any of them
}