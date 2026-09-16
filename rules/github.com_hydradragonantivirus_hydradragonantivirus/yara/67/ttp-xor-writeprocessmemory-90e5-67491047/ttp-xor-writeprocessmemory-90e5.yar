rule TTP_XOR_WriteProcessMemory_90e5 {
  strings:
    $key_90e5 = { c7 97 [2] f5 b5 [2] f3 80 [2] dd 80 [2] e2 9c }

  condition:
    any of them
}