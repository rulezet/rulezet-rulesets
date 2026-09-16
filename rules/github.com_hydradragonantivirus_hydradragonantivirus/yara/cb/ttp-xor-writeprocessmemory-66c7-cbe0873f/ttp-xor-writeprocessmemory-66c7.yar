rule TTP_XOR_WriteProcessMemory_66c7 {
  strings:
    $key_66c7 = { 31 b5 [2] 03 97 [2] 05 a2 [2] 2b a2 [2] 14 be }

  condition:
    any of them
}