rule TTP_XOR_WriteProcessMemory_f405 {
  strings:
    $key_f405 = { a3 77 [2] 91 55 [2] 97 60 [2] b9 60 [2] 86 7c }

  condition:
    any of them
}