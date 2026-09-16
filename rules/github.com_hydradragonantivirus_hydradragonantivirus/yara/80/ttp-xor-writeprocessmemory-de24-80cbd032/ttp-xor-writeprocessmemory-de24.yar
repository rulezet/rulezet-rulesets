rule TTP_XOR_WriteProcessMemory_de24 {
  strings:
    $key_de24 = { 89 56 [2] bb 74 [2] bd 41 [2] 93 41 [2] ac 5d }

  condition:
    any of them
}