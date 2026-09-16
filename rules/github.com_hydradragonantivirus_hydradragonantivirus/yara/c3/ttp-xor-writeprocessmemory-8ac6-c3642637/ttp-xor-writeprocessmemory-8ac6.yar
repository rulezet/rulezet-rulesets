rule TTP_XOR_WriteProcessMemory_8ac6 {
  strings:
    $key_8ac6 = { dd b4 [2] ef 96 [2] e9 a3 [2] c7 a3 [2] f8 bf }

  condition:
    any of them
}