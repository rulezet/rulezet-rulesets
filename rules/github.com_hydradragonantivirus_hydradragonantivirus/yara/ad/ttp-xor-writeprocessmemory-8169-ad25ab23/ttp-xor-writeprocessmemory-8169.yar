rule TTP_XOR_WriteProcessMemory_8169 {
  strings:
    $key_8169 = { d6 1b [2] e4 39 [2] e2 0c [2] cc 0c [2] f3 10 }

  condition:
    any of them
}