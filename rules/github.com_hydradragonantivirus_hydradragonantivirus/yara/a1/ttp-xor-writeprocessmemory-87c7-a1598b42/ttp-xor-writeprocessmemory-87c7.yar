rule TTP_XOR_WriteProcessMemory_87c7 {
  strings:
    $key_87c7 = { d0 b5 [2] e2 97 [2] e4 a2 [2] ca a2 [2] f5 be }

  condition:
    any of them
}