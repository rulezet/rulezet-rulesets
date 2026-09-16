rule TTP_XOR_WriteProcessMemory_90f3 {
  strings:
    $key_90f3 = { c7 81 [2] f5 a3 [2] f3 96 [2] dd 96 [2] e2 8a }

  condition:
    any of them
}