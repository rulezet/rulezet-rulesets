rule TTP_XOR_WriteProcessMemory_9325 {
  strings:
    $key_9325 = { c4 57 [2] f6 75 [2] f0 40 [2] de 40 [2] e1 5c }

  condition:
    any of them
}