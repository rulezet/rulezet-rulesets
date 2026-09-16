rule TTP_XOR_WriteProcessMemory_71c7 {
  strings:
    $key_71c7 = { 26 b5 [2] 14 97 [2] 12 a2 [2] 3c a2 [2] 03 be }

  condition:
    any of them
}