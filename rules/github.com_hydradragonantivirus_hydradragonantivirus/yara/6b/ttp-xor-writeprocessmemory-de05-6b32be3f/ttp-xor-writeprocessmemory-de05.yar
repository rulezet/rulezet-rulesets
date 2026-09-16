rule TTP_XOR_WriteProcessMemory_de05 {
  strings:
    $key_de05 = { 89 77 [2] bb 55 [2] bd 60 [2] 93 60 [2] ac 7c }

  condition:
    any of them
}