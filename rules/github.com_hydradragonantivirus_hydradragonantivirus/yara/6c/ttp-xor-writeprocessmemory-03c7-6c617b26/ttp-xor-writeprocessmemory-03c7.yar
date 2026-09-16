rule TTP_XOR_WriteProcessMemory_03c7 {
  strings:
    $key_03c7 = { 54 b5 [2] 66 97 [2] 60 a2 [2] 4e a2 [2] 71 be }

  condition:
    any of them
}