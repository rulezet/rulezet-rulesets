rule TTP_XOR_WriteProcessMemory_f400 {
  strings:
    $key_f400 = { a3 72 [2] 91 50 [2] 97 65 [2] b9 65 [2] 86 79 }

  condition:
    any of them
}