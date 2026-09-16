rule TTP_XOR_WriteProcessMemory_f2e4 {
  strings:
    $key_f2e4 = { a5 96 [2] 97 b4 [2] 91 81 [2] bf 81 [2] 80 9d }

  condition:
    any of them
}