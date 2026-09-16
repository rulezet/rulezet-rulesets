rule TTP_XOR_WriteProcessMemory_de36 {
  strings:
    $key_de36 = { 89 44 [2] bb 66 [2] bd 53 [2] 93 53 [2] ac 4f }

  condition:
    any of them
}