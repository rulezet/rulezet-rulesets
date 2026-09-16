rule TTP_XOR_WriteProcessMemory_def1 {
  strings:
    $key_def1 = { 89 83 [2] bb a1 [2] bd 94 [2] 93 94 [2] ac 88 }

  condition:
    any of them
}