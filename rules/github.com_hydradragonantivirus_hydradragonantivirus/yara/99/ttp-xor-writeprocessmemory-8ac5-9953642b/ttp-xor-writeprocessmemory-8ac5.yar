rule TTP_XOR_WriteProcessMemory_8ac5 {
  strings:
    $key_8ac5 = { dd b7 [2] ef 95 [2] e9 a0 [2] c7 a0 [2] f8 bc }

  condition:
    any of them
}