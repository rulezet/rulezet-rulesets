rule TTP_XOR_WriteProcessMemory_41c7 {
  strings:
    $key_41c7 = { 16 b5 [2] 24 97 [2] 22 a2 [2] 0c a2 [2] 33 be }

  condition:
    any of them
}