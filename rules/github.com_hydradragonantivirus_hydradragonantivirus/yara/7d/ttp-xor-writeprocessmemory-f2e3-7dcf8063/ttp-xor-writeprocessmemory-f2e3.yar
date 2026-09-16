rule TTP_XOR_WriteProcessMemory_f2e3 {
  strings:
    $key_f2e3 = { a5 91 [2] 97 b3 [2] 91 86 [2] bf 86 [2] 80 9a }

  condition:
    any of them
}