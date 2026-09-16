rule TTP_XOR_WriteProcessMemory_f4b1 {
  strings:
    $key_f4b1 = { a3 c3 [2] 91 e1 [2] 97 d4 [2] b9 d4 [2] 86 c8 }

  condition:
    any of them
}