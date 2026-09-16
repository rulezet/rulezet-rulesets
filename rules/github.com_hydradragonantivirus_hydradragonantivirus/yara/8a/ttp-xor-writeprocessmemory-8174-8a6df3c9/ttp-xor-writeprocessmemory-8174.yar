rule TTP_XOR_WriteProcessMemory_8174 {
  strings:
    $key_8174 = { d6 06 [2] e4 24 [2] e2 11 [2] cc 11 [2] f3 0d }

  condition:
    any of them
}