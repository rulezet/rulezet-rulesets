rule TTP_XOR_WriteProcessMemory_de47 {
  strings:
    $key_de47 = { 89 35 [2] bb 17 [2] bd 22 [2] 93 22 [2] ac 3e }

  condition:
    any of them
}