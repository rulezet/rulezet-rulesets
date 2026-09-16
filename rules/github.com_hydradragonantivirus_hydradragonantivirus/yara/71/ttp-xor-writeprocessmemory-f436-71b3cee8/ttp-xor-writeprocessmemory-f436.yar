rule TTP_XOR_WriteProcessMemory_f436 {
  strings:
    $key_f436 = { a3 44 [2] 91 66 [2] 97 53 [2] b9 53 [2] 86 4f }

  condition:
    any of them
}