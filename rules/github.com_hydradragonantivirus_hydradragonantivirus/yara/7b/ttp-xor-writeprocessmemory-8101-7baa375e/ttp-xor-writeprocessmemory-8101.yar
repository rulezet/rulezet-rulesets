rule TTP_XOR_WriteProcessMemory_8101 {
  strings:
    $key_8101 = { d6 73 [2] e4 51 [2] e2 64 [2] cc 64 [2] f3 78 }

  condition:
    any of them
}