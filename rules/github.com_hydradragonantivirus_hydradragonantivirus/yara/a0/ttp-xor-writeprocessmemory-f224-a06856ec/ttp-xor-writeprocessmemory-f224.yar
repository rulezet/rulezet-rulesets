rule TTP_XOR_WriteProcessMemory_f224 {
  strings:
    $key_f224 = { a5 56 [2] 97 74 [2] 91 41 [2] bf 41 [2] 80 5d }

  condition:
    any of them
}