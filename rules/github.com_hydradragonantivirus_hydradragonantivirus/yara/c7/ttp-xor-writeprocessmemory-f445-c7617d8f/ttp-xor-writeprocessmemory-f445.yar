rule TTP_XOR_WriteProcessMemory_f445 {
  strings:
    $key_f445 = { a3 37 [2] 91 15 [2] 97 20 [2] b9 20 [2] 86 3c }

  condition:
    any of them
}