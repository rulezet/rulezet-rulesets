rule TTP_XOR_WriteProcessMemory_f264 {
  strings:
    $key_f264 = { a5 16 [2] 97 34 [2] 91 01 [2] bf 01 [2] 80 1d }

  condition:
    any of them
}