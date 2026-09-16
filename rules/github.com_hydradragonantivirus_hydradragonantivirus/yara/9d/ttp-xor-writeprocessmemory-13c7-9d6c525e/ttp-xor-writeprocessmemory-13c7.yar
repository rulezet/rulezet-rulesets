rule TTP_XOR_WriteProcessMemory_13c7 {
  strings:
    $key_13c7 = { 44 b5 [2] 76 97 [2] 70 a2 [2] 5e a2 [2] 61 be }

  condition:
    any of them
}