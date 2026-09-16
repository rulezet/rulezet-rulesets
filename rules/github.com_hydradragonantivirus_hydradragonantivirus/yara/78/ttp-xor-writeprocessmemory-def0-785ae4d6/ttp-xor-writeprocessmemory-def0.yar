rule TTP_XOR_WriteProcessMemory_def0 {
  strings:
    $key_def0 = { 89 82 [2] bb a0 [2] bd 95 [2] 93 95 [2] ac 89 }

  condition:
    any of them
}