rule TTP_XOR_WriteProcessMemory_bde0 {
  strings:
    $key_bde0 = { ea 92 [2] d8 b0 [2] de 85 [2] f0 85 [2] cf 99 }

  condition:
    any of them
}