rule TTP_XOR_WriteProcessMemory_96e5 {
  strings:
    $key_96e5 = { c1 97 [2] f3 b5 [2] f5 80 [2] db 80 [2] e4 9c }

  condition:
    any of them
}