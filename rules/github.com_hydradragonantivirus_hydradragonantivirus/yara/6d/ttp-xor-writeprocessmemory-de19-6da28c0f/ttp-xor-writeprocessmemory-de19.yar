rule TTP_XOR_WriteProcessMemory_de19 {
  strings:
    $key_de19 = { 89 6b [2] bb 49 [2] bd 7c [2] 93 7c [2] ac 60 }

  condition:
    any of them
}