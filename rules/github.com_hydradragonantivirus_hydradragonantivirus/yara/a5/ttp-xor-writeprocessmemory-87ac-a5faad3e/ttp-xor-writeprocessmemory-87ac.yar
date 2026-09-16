rule TTP_XOR_WriteProcessMemory_87ac {
  strings:
    $key_87ac = { d0 de [2] e2 fc [2] e4 c9 [2] ca c9 [2] f5 d5 }

  condition:
    any of them
}