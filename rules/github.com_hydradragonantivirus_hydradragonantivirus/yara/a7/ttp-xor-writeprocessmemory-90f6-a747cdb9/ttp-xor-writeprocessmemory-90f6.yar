rule TTP_XOR_WriteProcessMemory_90f6 {
  strings:
    $key_90f6 = { c7 84 [2] f5 a6 [2] f3 93 [2] dd 93 [2] e2 8f }

  condition:
    any of them
}