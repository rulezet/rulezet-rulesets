rule TTP_XOR_WriteProcessMemory_de44 {
  strings:
    $key_de44 = { 89 36 [2] bb 14 [2] bd 21 [2] 93 21 [2] ac 3d }

  condition:
    any of them
}