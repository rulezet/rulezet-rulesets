rule TTP_XOR_WriteProcessMemory_00c7 {
  strings:
    $key_00c7 = { 57 b5 [2] 65 97 [2] 63 a2 [2] 4d a2 [2] 72 be }

  condition:
    any of them
}