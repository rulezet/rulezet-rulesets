rule TTP_XOR_WriteProcessMemory_87e5 {
  strings:
    $key_87e5 = { d0 97 [2] e2 b5 [2] e4 80 [2] ca 80 [2] f5 9c }

  condition:
    any of them
}