rule TTP_XOR_WriteProcessMemory_90f9 {
  strings:
    $key_90f9 = { c7 8b [2] f5 a9 [2] f3 9c [2] dd 9c [2] e2 80 }

  condition:
    any of them
}