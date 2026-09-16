rule TTP_XOR_WriteProcessMemory_8570 {
  strings:
    $key_8570 = { d2 02 [2] e0 20 [2] e6 15 [2] c8 15 [2] f7 09 }

  condition:
    any of them
}