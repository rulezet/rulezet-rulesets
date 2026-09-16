rule TTP_XOR_WriteProcessMemory_f4c3 {
  strings:
    $key_f4c3 = { a3 b1 [2] 91 93 [2] 97 a6 [2] b9 a6 [2] 86 ba }

  condition:
    any of them
}