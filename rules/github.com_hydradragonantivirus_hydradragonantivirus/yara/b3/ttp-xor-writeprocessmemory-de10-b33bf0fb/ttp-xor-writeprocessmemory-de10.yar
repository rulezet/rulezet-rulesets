rule TTP_XOR_WriteProcessMemory_de10 {
  strings:
    $key_de10 = { 89 62 [2] bb 40 [2] bd 75 [2] 93 75 [2] ac 69 }

  condition:
    any of them
}