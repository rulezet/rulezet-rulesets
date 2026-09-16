rule TTP_XOR_WriteProcessMemory_bdf3 {
  strings:
    $key_bdf3 = { ea 81 [2] d8 a3 [2] de 96 [2] f0 96 [2] cf 8a }

  condition:
    any of them
}