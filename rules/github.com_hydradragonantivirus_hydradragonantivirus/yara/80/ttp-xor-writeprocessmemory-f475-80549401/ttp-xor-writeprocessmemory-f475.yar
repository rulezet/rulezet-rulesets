rule TTP_XOR_WriteProcessMemory_f475 {
  strings:
    $key_f475 = { a3 07 [2] 91 25 [2] 97 10 [2] b9 10 [2] 86 0c }

  condition:
    any of them
}