rule TTP_XOR_WriteProcessMemory_8a83 {
  strings:
    $key_8a83 = { dd f1 [2] ef d3 [2] e9 e6 [2] c7 e6 [2] f8 fa }

  condition:
    any of them
}