rule TTP_XOR_WriteProcessMemory_f4e6 {
  strings:
    $key_f4e6 = { a3 94 [2] 91 b6 [2] 97 83 [2] b9 83 [2] 86 9f }

  condition:
    any of them
}