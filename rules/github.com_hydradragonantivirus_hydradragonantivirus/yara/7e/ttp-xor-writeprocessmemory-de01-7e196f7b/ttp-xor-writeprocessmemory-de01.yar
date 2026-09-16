rule TTP_XOR_WriteProcessMemory_de01 {
  strings:
    $key_de01 = { 89 73 [2] bb 51 [2] bd 64 [2] 93 64 [2] ac 78 }

  condition:
    any of them
}