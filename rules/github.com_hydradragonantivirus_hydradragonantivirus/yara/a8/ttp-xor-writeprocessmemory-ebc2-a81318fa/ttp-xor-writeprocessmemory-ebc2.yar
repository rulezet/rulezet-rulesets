rule TTP_XOR_WriteProcessMemory_ebc2 {
  strings:
    $key_ebc2 = { bc b0 [2] 8e 92 [2] 88 a7 [2] a6 a7 [2] 99 bb }

  condition:
    any of them
}