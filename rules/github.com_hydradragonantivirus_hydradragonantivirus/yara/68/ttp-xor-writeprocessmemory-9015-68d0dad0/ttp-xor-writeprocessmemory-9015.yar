rule TTP_XOR_WriteProcessMemory_9015 {
  strings:
    $key_9015 = { c7 67 [2] f5 45 [2] f3 70 [2] dd 70 [2] e2 6c }

  condition:
    any of them
}