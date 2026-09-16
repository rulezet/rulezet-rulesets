rule TTP_XOR_WriteProcessMemory_87e9 {
  strings:
    $key_87e9 = { d0 9b [2] e2 b9 [2] e4 8c [2] ca 8c [2] f5 90 }

  condition:
    any of them
}