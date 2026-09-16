rule TTP_XOR_WriteProcessMemory_aac2 {
  strings:
    $key_aac2 = { fd b0 [2] cf 92 [2] c9 a7 [2] e7 a7 [2] d8 bb }

  condition:
    any of them
}