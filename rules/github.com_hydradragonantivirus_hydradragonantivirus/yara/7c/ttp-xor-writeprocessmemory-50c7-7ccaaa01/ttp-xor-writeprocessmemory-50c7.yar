rule TTP_XOR_WriteProcessMemory_50c7 {
  strings:
    $key_50c7 = { 07 b5 [2] 35 97 [2] 33 a2 [2] 1d a2 [2] 22 be }

  condition:
    any of them
}