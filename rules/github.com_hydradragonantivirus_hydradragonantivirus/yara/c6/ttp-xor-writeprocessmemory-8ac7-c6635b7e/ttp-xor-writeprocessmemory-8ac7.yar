rule TTP_XOR_WriteProcessMemory_8ac7 {
  strings:
    $key_8ac7 = { dd b5 [2] ef 97 [2] e9 a2 [2] c7 a2 [2] f8 be }

  condition:
    any of them
}