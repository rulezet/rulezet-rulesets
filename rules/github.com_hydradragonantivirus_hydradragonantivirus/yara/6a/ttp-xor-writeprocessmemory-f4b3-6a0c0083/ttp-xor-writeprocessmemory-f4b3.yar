rule TTP_XOR_WriteProcessMemory_f4b3 {
  strings:
    $key_f4b3 = { a3 c1 [2] 91 e3 [2] 97 d6 [2] b9 d6 [2] 86 ca }

  condition:
    any of them
}