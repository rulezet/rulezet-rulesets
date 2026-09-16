rule TTP_XOR_WriteProcessMemory_9065 {
  strings:
    $key_9065 = { c7 17 [2] f5 35 [2] f3 00 [2] dd 00 [2] e2 1c }

  condition:
    any of them
}