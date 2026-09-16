rule TTP_XOR_WriteProcessMemory_9227 {
  strings:
    $key_9227 = { c5 55 [2] f7 77 [2] f1 42 [2] df 42 [2] e0 5e }

  condition:
    any of them
}