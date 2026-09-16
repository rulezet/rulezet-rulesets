rule TTP_XOR_WriteProcessMemory_90e8 {
  strings:
    $key_90e8 = { c7 9a [2] f5 b8 [2] f3 8d [2] dd 8d [2] e2 91 }

  condition:
    any of them
}