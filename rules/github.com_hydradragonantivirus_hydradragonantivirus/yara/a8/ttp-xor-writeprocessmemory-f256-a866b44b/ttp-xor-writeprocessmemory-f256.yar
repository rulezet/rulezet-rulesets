rule TTP_XOR_WriteProcessMemory_f256 {
  strings:
    $key_f256 = { a5 24 [2] 97 06 [2] 91 33 [2] bf 33 [2] 80 2f }

  condition:
    any of them
}