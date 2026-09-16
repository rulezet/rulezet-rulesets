rule TTP_XOR_WriteProcessMemory_de65 {
  strings:
    $key_de65 = { 89 17 [2] bb 35 [2] bd 00 [2] 93 00 [2] ac 1c }

  condition:
    any of them
}