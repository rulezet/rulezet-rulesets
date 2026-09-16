rule TTP_XOR_WriteProcessMemory_bd79 {
  strings:
    $key_bd79 = { ea 0b [2] d8 29 [2] de 1c [2] f0 1c [2] cf 00 }

  condition:
    any of them
}