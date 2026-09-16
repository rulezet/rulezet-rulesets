rule TTP_XOR_WriteProcessMemory_9625 {
  strings:
    $key_9625 = { c1 57 [2] f3 75 [2] f5 40 [2] db 40 [2] e4 5c }

  condition:
    any of them
}