rule TTP_XOR_WriteProcessMemory_90f2 {
  strings:
    $key_90f2 = { c7 80 [2] f5 a2 [2] f3 97 [2] dd 97 [2] e2 8b }

  condition:
    any of them
}