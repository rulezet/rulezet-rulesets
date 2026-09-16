rule TTP_XOR_WriteProcessMemory_8111 {
  strings:
    $key_8111 = { d6 63 [2] e4 41 [2] e2 74 [2] cc 74 [2] f3 68 }

  condition:
    any of them
}