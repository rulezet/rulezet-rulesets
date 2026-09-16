rule TTP_XOR_WriteProcessMemory_de53 {
  strings:
    $key_de53 = { 89 21 [2] bb 03 [2] bd 36 [2] 93 36 [2] ac 2a }

  condition:
    any of them
}