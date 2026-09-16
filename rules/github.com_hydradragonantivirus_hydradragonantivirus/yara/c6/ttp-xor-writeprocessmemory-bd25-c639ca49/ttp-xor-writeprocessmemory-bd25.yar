rule TTP_XOR_WriteProcessMemory_bd25 {
  strings:
    $key_bd25 = { ea 57 [2] d8 75 [2] de 40 [2] f0 40 [2] cf 5c }

  condition:
    any of them
}