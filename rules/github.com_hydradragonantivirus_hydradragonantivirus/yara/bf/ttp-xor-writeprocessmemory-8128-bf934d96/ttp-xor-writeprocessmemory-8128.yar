rule TTP_XOR_WriteProcessMemory_8128 {
  strings:
    $key_8128 = { d6 5a [2] e4 78 [2] e2 4d [2] cc 4d [2] f3 51 }

  condition:
    any of them
}