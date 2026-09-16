rule TTP_XOR_WriteProcessMemory_8138 {
  strings:
    $key_8138 = { d6 4a [2] e4 68 [2] e2 5d [2] cc 5d [2] f3 41 }

  condition:
    any of them
}