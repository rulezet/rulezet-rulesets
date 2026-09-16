rule TTP_XOR_WriteProcessMemory_f232 {
  strings:
    $key_f232 = { a5 40 [2] 97 62 [2] 91 57 [2] bf 57 [2] 80 4b }

  condition:
    any of them
}