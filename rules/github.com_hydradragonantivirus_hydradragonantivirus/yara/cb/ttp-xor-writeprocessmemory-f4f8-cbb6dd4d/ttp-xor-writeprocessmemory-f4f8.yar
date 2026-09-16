rule TTP_XOR_WriteProcessMemory_f4f8 {
  strings:
    $key_f4f8 = { a3 8a [2] 91 a8 [2] 97 9d [2] b9 9d [2] 86 81 }

  condition:
    any of them
}