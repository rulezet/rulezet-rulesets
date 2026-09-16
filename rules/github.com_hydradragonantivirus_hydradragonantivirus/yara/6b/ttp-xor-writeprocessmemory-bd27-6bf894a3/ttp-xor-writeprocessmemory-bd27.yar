rule TTP_XOR_WriteProcessMemory_bd27 {
  strings:
    $key_bd27 = { ea 55 [2] d8 77 [2] de 42 [2] f0 42 [2] cf 5e }

  condition:
    any of them
}