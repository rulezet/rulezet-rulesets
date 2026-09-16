rule TTP_XOR_WriteProcessMemory_de49 {
  strings:
    $key_de49 = { 89 3b [2] bb 19 [2] bd 2c [2] 93 2c [2] ac 30 }

  condition:
    any of them
}