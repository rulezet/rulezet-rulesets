rule TTP_XOR_WriteProcessMemory_90e3 {
  strings:
    $key_90e3 = { c7 91 [2] f5 b3 [2] f3 86 [2] dd 86 [2] e2 9a }

  condition:
    any of them
}