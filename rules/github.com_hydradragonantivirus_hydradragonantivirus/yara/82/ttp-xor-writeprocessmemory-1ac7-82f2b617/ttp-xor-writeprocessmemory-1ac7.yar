rule TTP_XOR_WriteProcessMemory_1ac7 {
  strings:
    $key_1ac7 = { 4d b5 [2] 7f 97 [2] 79 a2 [2] 57 a2 [2] 68 be }

  condition:
    any of them
}