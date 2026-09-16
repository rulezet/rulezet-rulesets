rule TTP_XOR_WriteProcessMemory_f4b0 {
  strings:
    $key_f4b0 = { a3 c2 [2] 91 e0 [2] 97 d5 [2] b9 d5 [2] 86 c9 }

  condition:
    any of them
}