rule TTP_XOR_WriteProcessMemory_f271 {
  strings:
    $key_f271 = { a5 03 [2] 97 21 [2] 91 14 [2] bf 14 [2] 80 08 }

  condition:
    any of them
}