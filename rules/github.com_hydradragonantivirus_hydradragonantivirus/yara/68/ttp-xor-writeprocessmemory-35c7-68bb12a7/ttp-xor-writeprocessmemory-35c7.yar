rule TTP_XOR_WriteProcessMemory_35c7 {
  strings:
    $key_35c7 = { 62 b5 [2] 50 97 [2] 56 a2 [2] 78 a2 [2] 47 be }

  condition:
    any of them
}