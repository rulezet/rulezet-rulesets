rule TTP_XOR_WriteProcessMemory_9745 {
  strings:
    $key_9745 = { c0 37 [2] f2 15 [2] f4 20 [2] da 20 [2] e5 3c }

  condition:
    any of them
}