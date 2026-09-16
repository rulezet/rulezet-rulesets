rule TTP_XOR_WriteProcessMemory_9127 {
  strings:
    $key_9127 = { c6 55 [2] f4 77 [2] f2 42 [2] dc 42 [2] e3 5e }

  condition:
    any of them
}