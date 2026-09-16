rule TTP_XOR_WriteProcessMemory_9175 {
  strings:
    $key_9175 = { c6 07 [2] f4 25 [2] f2 10 [2] dc 10 [2] e3 0c }

  condition:
    any of them
}