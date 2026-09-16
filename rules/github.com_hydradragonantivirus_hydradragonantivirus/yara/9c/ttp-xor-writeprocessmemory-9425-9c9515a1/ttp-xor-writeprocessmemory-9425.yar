rule TTP_XOR_WriteProcessMemory_9425 {
  strings:
    $key_9425 = { c3 57 [2] f1 75 [2] f7 40 [2] d9 40 [2] e6 5c }

  condition:
    any of them
}