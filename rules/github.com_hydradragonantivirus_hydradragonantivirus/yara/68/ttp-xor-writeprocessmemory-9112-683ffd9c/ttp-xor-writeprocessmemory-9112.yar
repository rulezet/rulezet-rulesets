rule TTP_XOR_WriteProcessMemory_9112 {
  strings:
    $key_9112 = { c6 60 [2] f4 42 [2] f2 77 [2] dc 77 [2] e3 6b }

  condition:
    any of them
}