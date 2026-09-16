rule TTP_XOR_WriteProcessMemory_f4d4 {
  strings:
    $key_f4d4 = { a3 a6 [2] 91 84 [2] 97 b1 [2] b9 b1 [2] 86 ad }

  condition:
    any of them
}