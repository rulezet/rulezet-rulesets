rule TTP_XOR_WriteProcessMemory_33c7 {
  strings:
    $key_33c7 = { 64 b5 [2] 56 97 [2] 50 a2 [2] 7e a2 [2] 41 be }

  condition:
    any of them
}