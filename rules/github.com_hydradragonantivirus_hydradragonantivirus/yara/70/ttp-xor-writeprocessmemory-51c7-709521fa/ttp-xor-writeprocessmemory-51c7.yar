rule TTP_XOR_WriteProcessMemory_51c7 {
  strings:
    $key_51c7 = { 06 b5 [2] 34 97 [2] 32 a2 [2] 1c a2 [2] 23 be }

  condition:
    any of them
}