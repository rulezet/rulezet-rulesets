rule TTP_XOR_WriteProcessMemory_73c7 {
  strings:
    $key_73c7 = { 24 b5 [2] 16 97 [2] 10 a2 [2] 3e a2 [2] 01 be }

  condition:
    any of them
}