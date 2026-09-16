rule TTP_XOR_WriteProcessMemory_93e5 {
  strings:
    $key_93e5 = { c4 97 [2] f6 b5 [2] f0 80 [2] de 80 [2] e1 9c }

  condition:
    any of them
}