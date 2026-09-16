rule TTP_XOR_WriteProcessMemory_f263 {
  strings:
    $key_f263 = { a5 11 [2] 97 33 [2] 91 06 [2] bf 06 [2] 80 1a }

  condition:
    any of them
}