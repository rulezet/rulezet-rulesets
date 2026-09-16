rule TTP_XOR_WriteProcessMemory_93e8 {
  strings:
    $key_93e8 = { c4 9a [2] f6 b8 [2] f0 8d [2] de 8d [2] e1 91 }

  condition:
    any of them
}