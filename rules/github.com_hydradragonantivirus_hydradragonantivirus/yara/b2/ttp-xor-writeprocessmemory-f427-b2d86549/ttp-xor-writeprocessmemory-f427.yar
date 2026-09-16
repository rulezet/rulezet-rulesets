rule TTP_XOR_WriteProcessMemory_f427 {
  strings:
    $key_f427 = { a3 55 [2] 91 77 [2] 97 42 [2] b9 42 [2] 86 5e }

  condition:
    any of them
}