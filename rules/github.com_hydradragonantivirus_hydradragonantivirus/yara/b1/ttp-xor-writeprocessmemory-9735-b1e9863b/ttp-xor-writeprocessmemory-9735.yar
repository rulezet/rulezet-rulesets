rule TTP_XOR_WriteProcessMemory_9735 {
  strings:
    $key_9735 = { c0 47 [2] f2 65 [2] f4 50 [2] da 50 [2] e5 4c }

  condition:
    any of them
}