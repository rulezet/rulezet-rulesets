rule TTP_XOR_WriteProcessMemory_bd40 {
  strings:
    $key_bd40 = { ea 32 [2] d8 10 [2] de 25 [2] f0 25 [2] cf 39 }

  condition:
    any of them
}