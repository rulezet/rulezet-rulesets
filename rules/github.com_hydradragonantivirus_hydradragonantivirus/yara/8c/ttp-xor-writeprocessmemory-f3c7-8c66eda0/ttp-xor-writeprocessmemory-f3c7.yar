rule TTP_XOR_WriteProcessMemory_f3c7 {
  strings:
    $key_f3c7 = { a4 b5 [2] 96 97 [2] 90 a2 [2] be a2 [2] 81 be }

  condition:
    any of them
}