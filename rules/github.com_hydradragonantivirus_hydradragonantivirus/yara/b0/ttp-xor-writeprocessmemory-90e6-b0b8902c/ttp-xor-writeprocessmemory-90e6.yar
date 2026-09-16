rule TTP_XOR_WriteProcessMemory_90e6 {
  strings:
    $key_90e6 = { c7 94 [2] f5 b6 [2] f3 83 [2] dd 83 [2] e2 9f }

  condition:
    any of them
}