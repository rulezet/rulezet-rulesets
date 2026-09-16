rule TTP_XOR_WriteProcessMemory_de51 {
  strings:
    $key_de51 = { 89 23 [2] bb 01 [2] bd 34 [2] 93 34 [2] ac 28 }

  condition:
    any of them
}