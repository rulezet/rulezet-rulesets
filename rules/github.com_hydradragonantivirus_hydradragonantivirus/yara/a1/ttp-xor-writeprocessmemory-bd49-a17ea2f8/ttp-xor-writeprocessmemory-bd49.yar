rule TTP_XOR_WriteProcessMemory_bd49 {
  strings:
    $key_bd49 = { ea 3b [2] d8 19 [2] de 2c [2] f0 2c [2] cf 30 }

  condition:
    any of them
}