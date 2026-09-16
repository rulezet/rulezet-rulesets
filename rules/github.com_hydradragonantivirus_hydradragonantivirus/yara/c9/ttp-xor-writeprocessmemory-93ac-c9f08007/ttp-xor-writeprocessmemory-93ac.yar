rule TTP_XOR_WriteProcessMemory_93ac {
  strings:
    $key_93ac = { c4 de [2] f6 fc [2] f0 c9 [2] de c9 [2] e1 d5 }

  condition:
    any of them
}