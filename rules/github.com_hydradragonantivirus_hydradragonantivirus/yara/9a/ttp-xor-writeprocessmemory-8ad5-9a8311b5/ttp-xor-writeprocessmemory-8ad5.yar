rule TTP_XOR_WriteProcessMemory_8ad5 {
  strings:
    $key_8ad5 = { dd a7 [2] ef 85 [2] e9 b0 [2] c7 b0 [2] f8 ac }

  condition:
    any of them
}