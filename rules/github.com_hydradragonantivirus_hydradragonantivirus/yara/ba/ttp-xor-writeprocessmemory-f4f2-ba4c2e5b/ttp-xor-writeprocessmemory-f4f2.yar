rule TTP_XOR_WriteProcessMemory_f4f2 {
  strings:
    $key_f4f2 = { a3 80 [2] 91 a2 [2] 97 97 [2] b9 97 [2] 86 8b }

  condition:
    any of them
}