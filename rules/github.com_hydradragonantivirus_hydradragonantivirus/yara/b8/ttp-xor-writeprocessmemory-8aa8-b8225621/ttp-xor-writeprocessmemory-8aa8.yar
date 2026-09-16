rule TTP_XOR_WriteProcessMemory_8aa8 {
  strings:
    $key_8aa8 = { dd da [2] ef f8 [2] e9 cd [2] c7 cd [2] f8 d1 }

  condition:
    any of them
}