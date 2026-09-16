rule TTP_XOR_WriteProcessMemory_f213 {
  strings:
    $key_f213 = { a5 61 [2] 97 43 [2] 91 76 [2] bf 76 [2] 80 6a }

  condition:
    any of them
}