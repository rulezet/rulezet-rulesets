rule TTP_XOR_WriteProcessMemory_f202 {
  strings:
    $key_f202 = { a5 70 [2] 97 52 [2] 91 67 [2] bf 67 [2] 80 7b }

  condition:
    any of them
}