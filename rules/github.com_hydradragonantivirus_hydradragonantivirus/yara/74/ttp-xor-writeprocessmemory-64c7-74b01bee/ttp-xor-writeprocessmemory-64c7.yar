rule TTP_XOR_WriteProcessMemory_64c7 {
  strings:
    $key_64c7 = { 33 b5 [2] 01 97 [2] 07 a2 [2] 29 a2 [2] 16 be }

  condition:
    any of them
}