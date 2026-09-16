rule TTP_XOR_WriteProcessMemory_8ab8 {
  strings:
    $key_8ab8 = { dd ca [2] ef e8 [2] e9 dd [2] c7 dd [2] f8 c1 }

  condition:
    any of them
}