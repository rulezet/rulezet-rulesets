rule TTP_XOR_WriteProcessMemory_f235 {
  strings:
    $key_f235 = { a5 47 [2] 97 65 [2] 91 50 [2] bf 50 [2] 80 4c }

  condition:
    any of them
}