rule TTP_XOR_WriteProcessMemory_f4c0 {
  strings:
    $key_f4c0 = { a3 b2 [2] 91 90 [2] 97 a5 [2] b9 a5 [2] 86 b9 }

  condition:
    any of them
}