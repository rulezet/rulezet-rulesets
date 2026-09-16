rule TTP_XOR_WriteProcessMemory_de40 {
  strings:
    $key_de40 = { 89 32 [2] bb 10 [2] bd 25 [2] 93 25 [2] ac 39 }

  condition:
    any of them
}