rule TTP_XOR_WriteProcessMemory_de03 {
  strings:
    $key_de03 = { 89 71 [2] bb 53 [2] bd 66 [2] 93 66 [2] ac 7a }

  condition:
    any of them
}