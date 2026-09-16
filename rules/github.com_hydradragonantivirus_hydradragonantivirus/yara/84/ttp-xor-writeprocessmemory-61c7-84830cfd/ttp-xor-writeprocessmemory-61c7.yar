rule TTP_XOR_WriteProcessMemory_61c7 {
  strings:
    $key_61c7 = { 36 b5 [2] 04 97 [2] 02 a2 [2] 2c a2 [2] 13 be }

  condition:
    any of them
}