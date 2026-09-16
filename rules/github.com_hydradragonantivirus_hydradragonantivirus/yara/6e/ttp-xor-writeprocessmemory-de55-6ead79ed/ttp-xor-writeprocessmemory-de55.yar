rule TTP_XOR_WriteProcessMemory_de55 {
  strings:
    $key_de55 = { 89 27 [2] bb 05 [2] bd 30 [2] 93 30 [2] ac 2c }

  condition:
    any of them
}