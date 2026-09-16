rule TTP_XOR_WriteProcessMemory_def2 {
  strings:
    $key_def2 = { 89 80 [2] bb a2 [2] bd 97 [2] 93 97 [2] ac 8b }

  condition:
    any of them
}