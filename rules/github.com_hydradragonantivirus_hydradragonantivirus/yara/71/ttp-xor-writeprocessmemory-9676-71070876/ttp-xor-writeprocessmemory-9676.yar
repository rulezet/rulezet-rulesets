rule TTP_XOR_WriteProcessMemory_9676 {
  strings:
    $key_9676 = { c1 04 [2] f3 26 [2] f5 13 [2] db 13 [2] e4 0f }

  condition:
    any of them
}