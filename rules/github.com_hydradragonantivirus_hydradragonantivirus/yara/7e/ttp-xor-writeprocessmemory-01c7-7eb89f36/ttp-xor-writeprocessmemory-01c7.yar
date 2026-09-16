rule TTP_XOR_WriteProcessMemory_01c7 {
  strings:
    $key_01c7 = { 56 b5 [2] 64 97 [2] 62 a2 [2] 4c a2 [2] 73 be }

  condition:
    any of them
}