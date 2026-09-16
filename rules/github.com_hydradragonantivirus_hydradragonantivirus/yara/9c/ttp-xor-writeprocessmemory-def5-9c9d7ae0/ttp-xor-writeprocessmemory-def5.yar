rule TTP_XOR_WriteProcessMemory_def5 {
  strings:
    $key_def5 = { 89 87 [2] bb a5 [2] bd 90 [2] 93 90 [2] ac 8c }

  condition:
    any of them
}