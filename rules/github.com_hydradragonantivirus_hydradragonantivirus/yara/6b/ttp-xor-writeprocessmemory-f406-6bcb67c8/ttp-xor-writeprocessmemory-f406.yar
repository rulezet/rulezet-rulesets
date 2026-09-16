rule TTP_XOR_WriteProcessMemory_f406 {
  strings:
    $key_f406 = { a3 74 [2] 91 56 [2] 97 63 [2] b9 63 [2] 86 7f }

  condition:
    any of them
}