rule TTP_XOR_WriteProcessMemory_f2a4 {
  strings:
    $key_f2a4 = { a5 d6 [2] 97 f4 [2] 91 c1 [2] bf c1 [2] 80 dd }

  condition:
    any of them
}