rule TTP_XOR_WriteProcessMemory_02c7 {
  strings:
    $key_02c7 = { 55 b5 [2] 67 97 [2] 61 a2 [2] 4f a2 [2] 70 be }

  condition:
    any of them
}