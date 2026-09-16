rule TTP_XOR_WriteProcessMemory_def6 {
  strings:
    $key_def6 = { 89 84 [2] bb a6 [2] bd 93 [2] 93 93 [2] ac 8f }

  condition:
    any of them
}