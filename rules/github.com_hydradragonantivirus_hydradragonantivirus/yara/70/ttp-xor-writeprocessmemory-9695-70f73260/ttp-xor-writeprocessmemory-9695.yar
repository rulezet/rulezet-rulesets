rule TTP_XOR_WriteProcessMemory_9695 {
  strings:
    $key_9695 = { c1 e7 [2] f3 c5 [2] f5 f0 [2] db f0 [2] e4 ec }

  condition:
    any of them
}