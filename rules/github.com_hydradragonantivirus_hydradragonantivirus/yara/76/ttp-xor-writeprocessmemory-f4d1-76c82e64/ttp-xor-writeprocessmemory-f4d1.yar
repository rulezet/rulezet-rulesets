rule TTP_XOR_WriteProcessMemory_f4d1 {
  strings:
    $key_f4d1 = { a3 a3 [2] 91 81 [2] 97 b4 [2] b9 b4 [2] 86 a8 }

  condition:
    any of them
}