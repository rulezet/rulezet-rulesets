rule TTP_XOR_WriteProcessMemory_bd03 {
  strings:
    $key_bd03 = { ea 71 [2] d8 53 [2] de 66 [2] f0 66 [2] cf 7a }

  condition:
    any of them
}