rule TTP_XOR_WriteProcessMemory_17c7 {
  strings:
    $key_17c7 = { 40 b5 [2] 72 97 [2] 74 a2 [2] 5a a2 [2] 65 be }

  condition:
    any of them
}