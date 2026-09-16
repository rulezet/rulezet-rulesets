rule TTP_XOR_WriteProcessMemory_90e7 {
  strings:
    $key_90e7 = { c7 95 [2] f5 b7 [2] f3 82 [2] dd 82 [2] e2 9e }

  condition:
    any of them
}