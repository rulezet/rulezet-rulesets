rule TTP_XOR_WriteProcessMemory_f2b6 {
  strings:
    $key_f2b6 = { a5 c4 [2] 97 e6 [2] 91 d3 [2] bf d3 [2] 80 cf }

  condition:
    any of them
}