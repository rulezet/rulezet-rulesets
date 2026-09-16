rule TTP_XOR_WriteProcessMemory_f47c {
  strings:
    $key_f47c = { a3 0e [2] 91 2c [2] 97 19 [2] b9 19 [2] 86 05 }

  condition:
    any of them
}