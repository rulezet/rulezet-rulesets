rule TTP_XOR_WriteProcessMemory_8245 {
  strings:
    $key_8245 = { d5 37 [2] e7 15 [2] e1 20 [2] cf 20 [2] f0 3c }

  condition:
    any of them
}