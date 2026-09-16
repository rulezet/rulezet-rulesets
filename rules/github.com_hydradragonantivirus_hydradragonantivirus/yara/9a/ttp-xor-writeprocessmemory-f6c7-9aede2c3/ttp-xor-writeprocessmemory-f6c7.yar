rule TTP_XOR_WriteProcessMemory_f6c7 {
  strings:
    $key_f6c7 = { a1 b5 [2] 93 97 [2] 95 a2 [2] bb a2 [2] 84 be }

  condition:
    any of them
}