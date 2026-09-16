rule TTP_XOR_WriteProcessMemory_f5c7 {
  strings:
    $key_f5c7 = { a2 b5 [2] 90 97 [2] 96 a2 [2] b8 a2 [2] 87 be }

  condition:
    any of them
}