rule TTP_XOR_WriteProcessMemory_de33 {
  strings:
    $key_de33 = { 89 41 [2] bb 63 [2] bd 56 [2] 93 56 [2] ac 4a }

  condition:
    any of them
}