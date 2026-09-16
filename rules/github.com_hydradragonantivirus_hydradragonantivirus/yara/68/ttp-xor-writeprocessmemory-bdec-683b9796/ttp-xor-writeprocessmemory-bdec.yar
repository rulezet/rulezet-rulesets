rule TTP_XOR_WriteProcessMemory_bdec {
  strings:
    $key_bdec = { ea 9e [2] d8 bc [2] de 89 [2] f0 89 [2] cf 95 }

  condition:
    any of them
}