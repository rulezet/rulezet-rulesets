rule TTP_XOR_WriteProcessMemory_9067 {
  strings:
    $key_9067 = { c7 15 [2] f5 37 [2] f3 02 [2] dd 02 [2] e2 1e }

  condition:
    any of them
}