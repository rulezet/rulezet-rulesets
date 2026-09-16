rule TTP_XOR_WriteProcessMemory_f446 {
  strings:
    $key_f446 = { a3 34 [2] 91 16 [2] 97 23 [2] b9 23 [2] 86 3f }

  condition:
    any of them
}