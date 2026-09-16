rule TTP_XOR_WriteProcessMemory_8118 {
  strings:
    $key_8118 = { d6 6a [2] e4 48 [2] e2 7d [2] cc 7d [2] f3 61 }

  condition:
    any of them
}