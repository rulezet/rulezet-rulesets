rule TTP_XOR_WriteProcessMemory_ac55 {
  strings:
    $key_ac55 = { fb 27 [2] c9 05 [2] cf 30 [2] e1 30 [2] de 2c }

  condition:
    any of them
}