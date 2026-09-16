rule TTP_XOR_WriteProcessMemory_45c7 {
  strings:
    $key_45c7 = { 12 b5 [2] 20 97 [2] 26 a2 [2] 08 a2 [2] 37 be }

  condition:
    any of them
}