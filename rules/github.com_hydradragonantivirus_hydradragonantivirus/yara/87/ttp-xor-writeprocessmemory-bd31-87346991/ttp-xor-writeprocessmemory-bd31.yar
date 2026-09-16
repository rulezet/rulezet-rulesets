rule TTP_XOR_WriteProcessMemory_bd31 {
  strings:
    $key_bd31 = { ea 43 [2] d8 61 [2] de 54 [2] f0 54 [2] cf 48 }

  condition:
    any of them
}