rule TTP_XOR_WriteProcessMemory_f497 {
  strings:
    $key_f497 = { a3 e5 [2] 91 c7 [2] 97 f2 [2] b9 f2 [2] 86 ee }

  condition:
    any of them
}