rule TTP_XOR_WriteProcessMemory_bd77 {
  strings:
    $key_bd77 = { ea 05 [2] d8 27 [2] de 12 [2] f0 12 [2] cf 0e }

  condition:
    any of them
}