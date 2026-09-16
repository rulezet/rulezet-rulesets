rule TTP_XOR_WriteProcessMemory_de32 {
  strings:
    $key_de32 = { 89 40 [2] bb 62 [2] bd 57 [2] 93 57 [2] ac 4b }

  condition:
    any of them
}