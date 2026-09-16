rule TTP_XOR_WriteProcessMemory_9007 {
  strings:
    $key_9007 = { c7 75 [2] f5 57 [2] f3 62 [2] dd 62 [2] e2 7e }

  condition:
    any of them
}