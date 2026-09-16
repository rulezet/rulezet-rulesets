rule TTP_XOR_WriteProcessMemory_8735 {
  strings:
    $key_8735 = { d0 47 [2] e2 65 [2] e4 50 [2] ca 50 [2] f5 4c }

  condition:
    any of them
}