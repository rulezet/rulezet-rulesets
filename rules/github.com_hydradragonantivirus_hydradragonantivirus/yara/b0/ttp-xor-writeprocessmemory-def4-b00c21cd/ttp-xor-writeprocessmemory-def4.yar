rule TTP_XOR_WriteProcessMemory_def4 {
  strings:
    $key_def4 = { 89 86 [2] bb a4 [2] bd 91 [2] 93 91 [2] ac 8d }

  condition:
    any of them
}