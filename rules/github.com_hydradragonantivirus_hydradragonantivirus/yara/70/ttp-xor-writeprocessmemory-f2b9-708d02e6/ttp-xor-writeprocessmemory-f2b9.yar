rule TTP_XOR_WriteProcessMemory_f2b9 {
  strings:
    $key_f2b9 = { a5 cb [2] 97 e9 [2] 91 dc [2] bf dc [2] 80 c0 }

  condition:
    any of them
}