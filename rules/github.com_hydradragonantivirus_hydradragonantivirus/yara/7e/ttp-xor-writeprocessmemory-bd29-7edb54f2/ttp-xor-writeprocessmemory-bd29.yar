rule TTP_XOR_WriteProcessMemory_bd29 {
  strings:
    $key_bd29 = { ea 5b [2] d8 79 [2] de 4c [2] f0 4c [2] cf 50 }

  condition:
    any of them
}