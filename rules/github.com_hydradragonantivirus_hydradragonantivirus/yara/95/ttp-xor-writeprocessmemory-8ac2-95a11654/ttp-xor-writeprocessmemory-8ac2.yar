rule TTP_XOR_WriteProcessMemory_8ac2 {
  strings:
    $key_8ac2 = { dd b0 [2] ef 92 [2] e9 a7 [2] c7 a7 [2] f8 bb }

  condition:
    any of them
}