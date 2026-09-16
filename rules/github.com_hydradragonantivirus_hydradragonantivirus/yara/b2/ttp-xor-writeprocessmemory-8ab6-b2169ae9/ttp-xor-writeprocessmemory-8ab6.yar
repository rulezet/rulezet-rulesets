rule TTP_XOR_WriteProcessMemory_8ab6 {
  strings:
    $key_8ab6 = { dd c4 [2] ef e6 [2] e9 d3 [2] c7 d3 [2] f8 cf }

  condition:
    any of them
}