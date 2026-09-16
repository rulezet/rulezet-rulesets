rule TTP_XOR_WriteProcessMemory_55c7 {
  strings:
    $key_55c7 = { 02 b5 [2] 30 97 [2] 36 a2 [2] 18 a2 [2] 27 be }

  condition:
    any of them
}