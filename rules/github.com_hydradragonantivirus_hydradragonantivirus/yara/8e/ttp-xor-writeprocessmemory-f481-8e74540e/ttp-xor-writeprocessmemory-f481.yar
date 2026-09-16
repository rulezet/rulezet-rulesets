rule TTP_XOR_WriteProcessMemory_f481 {
  strings:
    $key_f481 = { a3 f3 [2] 91 d1 [2] 97 e4 [2] b9 e4 [2] 86 f8 }

  condition:
    any of them
}