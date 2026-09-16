rule TTP_XOR_WriteProcessMemory_04c7 {
  strings:
    $key_04c7 = { 53 b5 [2] 61 97 [2] 67 a2 [2] 49 a2 [2] 76 be }

  condition:
    any of them
}