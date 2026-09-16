rule TTP_XOR_WriteProcessMemory_f270 {
  strings:
    $key_f270 = { a5 02 [2] 97 20 [2] 91 15 [2] bf 15 [2] 80 09 }

  condition:
    any of them
}