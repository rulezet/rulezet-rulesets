rule TTP_XOR_WriteProcessMemory_9435 {
  strings:
    $key_9435 = { c3 47 [2] f1 65 [2] f7 50 [2] d9 50 [2] e6 4c }

  condition:
    any of them
}