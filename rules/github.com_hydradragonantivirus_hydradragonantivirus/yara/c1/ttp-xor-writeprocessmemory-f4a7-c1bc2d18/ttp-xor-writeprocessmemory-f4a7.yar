rule TTP_XOR_WriteProcessMemory_f4a7 {
  strings:
    $key_f4a7 = { a3 d5 [2] 91 f7 [2] 97 c2 [2] b9 c2 [2] 86 de }

  condition:
    any of them
}