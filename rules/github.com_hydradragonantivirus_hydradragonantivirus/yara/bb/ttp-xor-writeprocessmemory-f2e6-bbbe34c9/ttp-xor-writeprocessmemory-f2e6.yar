rule TTP_XOR_WriteProcessMemory_f2e6 {
  strings:
    $key_f2e6 = { a5 94 [2] 97 b6 [2] 91 83 [2] bf 83 [2] 80 9f }

  condition:
    any of them
}