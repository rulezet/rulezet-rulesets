rule TTP_XOR_WriteProcessMemory_de15 {
  strings:
    $key_de15 = { 89 67 [2] bb 45 [2] bd 70 [2] 93 70 [2] ac 6c }

  condition:
    any of them
}