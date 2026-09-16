rule TTP_XOR_WriteProcessMemory_de14 {
  strings:
    $key_de14 = { 89 66 [2] bb 44 [2] bd 71 [2] 93 71 [2] ac 6d }

  condition:
    any of them
}