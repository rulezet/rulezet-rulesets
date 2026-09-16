rule TTP_XOR_WriteProcessMemory_9615 {
  strings:
    $key_9615 = { c1 67 [2] f3 45 [2] f5 70 [2] db 70 [2] e4 6c }

  condition:
    any of them
}