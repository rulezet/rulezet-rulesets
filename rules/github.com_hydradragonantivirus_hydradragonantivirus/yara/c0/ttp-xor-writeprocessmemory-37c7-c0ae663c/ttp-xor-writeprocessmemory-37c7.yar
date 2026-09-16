rule TTP_XOR_WriteProcessMemory_37c7 {
  strings:
    $key_37c7 = { 60 b5 [2] 52 97 [2] 54 a2 [2] 7a a2 [2] 45 be }

  condition:
    any of them
}