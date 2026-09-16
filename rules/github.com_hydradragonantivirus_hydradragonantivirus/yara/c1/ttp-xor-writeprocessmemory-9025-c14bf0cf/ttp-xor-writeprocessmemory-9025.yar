rule TTP_XOR_WriteProcessMemory_9025 {
  strings:
    $key_9025 = { c7 57 [2] f5 75 [2] f3 40 [2] dd 40 [2] e2 5c }

  condition:
    any of them
}