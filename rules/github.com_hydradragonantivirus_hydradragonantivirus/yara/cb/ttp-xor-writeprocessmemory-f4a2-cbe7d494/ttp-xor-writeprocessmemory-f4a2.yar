rule TTP_XOR_WriteProcessMemory_f4a2 {
  strings:
    $key_f4a2 = { a3 d0 [2] 91 f2 [2] 97 c7 [2] b9 c7 [2] 86 db }

  condition:
    any of them
}