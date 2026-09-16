rule TTP_XOR_WriteProcessMemory_9115 {
  strings:
    $key_9115 = { c6 67 [2] f4 45 [2] f2 70 [2] dc 70 [2] e3 6c }

  condition:
    any of them
}