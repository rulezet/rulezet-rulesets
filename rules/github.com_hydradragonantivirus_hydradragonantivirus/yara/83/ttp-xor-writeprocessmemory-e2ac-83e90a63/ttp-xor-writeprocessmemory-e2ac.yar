rule TTP_XOR_WriteProcessMemory_e2ac {
  strings:
    $key_e2ac = { b5 de [2] 87 fc [2] 81 c9 [2] af c9 [2] 90 d5 }

  condition:
    any of them
}