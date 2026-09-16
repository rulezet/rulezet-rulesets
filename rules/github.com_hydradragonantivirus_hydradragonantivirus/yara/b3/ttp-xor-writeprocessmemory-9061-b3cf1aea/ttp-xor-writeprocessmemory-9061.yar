rule TTP_XOR_WriteProcessMemory_9061 {
  strings:
    $key_9061 = { c7 13 [2] f5 31 [2] f3 04 [2] dd 04 [2] e2 18 }

  condition:
    any of them
}