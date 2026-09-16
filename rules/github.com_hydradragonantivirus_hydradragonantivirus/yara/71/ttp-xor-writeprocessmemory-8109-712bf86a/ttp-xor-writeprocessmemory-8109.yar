rule TTP_XOR_WriteProcessMemory_8109 {
  strings:
    $key_8109 = { d6 7b [2] e4 59 [2] e2 6c [2] cc 6c [2] f3 70 }

  condition:
    any of them
}