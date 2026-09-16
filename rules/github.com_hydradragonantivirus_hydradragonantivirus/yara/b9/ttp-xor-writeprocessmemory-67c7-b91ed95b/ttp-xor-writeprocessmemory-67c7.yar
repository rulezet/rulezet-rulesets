rule TTP_XOR_WriteProcessMemory_67c7 {
  strings:
    $key_67c7 = { 30 b5 [2] 02 97 [2] 04 a2 [2] 2a a2 [2] 15 be }

  condition:
    any of them
}