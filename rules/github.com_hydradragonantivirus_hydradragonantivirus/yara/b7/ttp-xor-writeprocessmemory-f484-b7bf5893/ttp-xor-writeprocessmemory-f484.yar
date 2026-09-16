rule TTP_XOR_WriteProcessMemory_f484 {
  strings:
    $key_f484 = { a3 f6 [2] 91 d4 [2] 97 e1 [2] b9 e1 [2] 86 fd }

  condition:
    any of them
}