rule TTP_XOR_WriteProcessMemory_43c7 {
  strings:
    $key_43c7 = { 14 b5 [2] 26 97 [2] 20 a2 [2] 0e a2 [2] 31 be }

  condition:
    any of them
}