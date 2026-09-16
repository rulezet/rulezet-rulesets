rule TTP_XOR_WriteProcessMemory_8a87 {
  strings:
    $key_8a87 = { dd f5 [2] ef d7 [2] e9 e2 [2] c7 e2 [2] f8 fe }

  condition:
    any of them
}