rule TTP_XOR_WriteProcessMemory_bde7 {
  strings:
    $key_bde7 = { ea 95 [2] d8 b7 [2] de 82 [2] f0 82 [2] cf 9e }

  condition:
    any of them
}