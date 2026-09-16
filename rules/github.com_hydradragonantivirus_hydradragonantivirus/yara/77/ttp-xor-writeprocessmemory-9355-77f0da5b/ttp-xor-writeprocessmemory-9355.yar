rule TTP_XOR_WriteProcessMemory_9355 {
  strings:
    $key_9355 = { c4 27 [2] f6 05 [2] f0 30 [2] de 30 [2] e1 2c }

  condition:
    any of them
}