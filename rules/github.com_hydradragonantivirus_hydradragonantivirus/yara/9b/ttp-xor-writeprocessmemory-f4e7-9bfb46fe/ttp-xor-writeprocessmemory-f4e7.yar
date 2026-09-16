rule TTP_XOR_WriteProcessMemory_f4e7 {
  strings:
    $key_f4e7 = { a3 95 [2] 91 b7 [2] 97 82 [2] b9 82 [2] 86 9e }

  condition:
    any of them
}