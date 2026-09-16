rule TTP_XOR_WriteProcessMemory_f449 {
  strings:
    $key_f449 = { a3 3b [2] 91 19 [2] 97 2c [2] b9 2c [2] 86 30 }

  condition:
    any of them
}