rule TTP_XOR_WriteProcessMemory_15c7 {
  strings:
    $key_15c7 = { 42 b5 [2] 70 97 [2] 76 a2 [2] 58 a2 [2] 67 be }

  condition:
    any of them
}