rule TTP_XOR_WriteProcessMemory_f4a1 {
  strings:
    $key_f4a1 = { a3 d3 [2] 91 f1 [2] 97 c4 [2] b9 c4 [2] 86 d8 }

  condition:
    any of them
}