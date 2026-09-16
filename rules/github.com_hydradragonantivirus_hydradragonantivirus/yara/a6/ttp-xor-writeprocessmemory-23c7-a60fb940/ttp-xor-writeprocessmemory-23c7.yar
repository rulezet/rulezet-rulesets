rule TTP_XOR_WriteProcessMemory_23c7 {
  strings:
    $key_23c7 = { 74 b5 [2] 46 97 [2] 40 a2 [2] 6e a2 [2] 51 be }

  condition:
    any of them
}