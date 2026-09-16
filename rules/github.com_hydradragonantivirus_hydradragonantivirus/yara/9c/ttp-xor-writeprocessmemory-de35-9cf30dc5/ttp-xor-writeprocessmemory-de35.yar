rule TTP_XOR_WriteProcessMemory_de35 {
  strings:
    $key_de35 = { 89 47 [2] bb 65 [2] bd 50 [2] 93 50 [2] ac 4c }

  condition:
    any of them
}