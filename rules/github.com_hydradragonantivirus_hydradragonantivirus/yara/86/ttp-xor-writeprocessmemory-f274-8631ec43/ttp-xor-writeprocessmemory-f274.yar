rule TTP_XOR_WriteProcessMemory_f274 {
  strings:
    $key_f274 = { a5 06 [2] 97 24 [2] 91 11 [2] bf 11 [2] 80 0d }

  condition:
    any of them
}