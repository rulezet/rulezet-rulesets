rule TTP_XOR_WriteProcessMemory_9545 {
  strings:
    $key_9545 = { c2 37 [2] f0 15 [2] f6 20 [2] d8 20 [2] e7 3c }

  condition:
    any of them
}