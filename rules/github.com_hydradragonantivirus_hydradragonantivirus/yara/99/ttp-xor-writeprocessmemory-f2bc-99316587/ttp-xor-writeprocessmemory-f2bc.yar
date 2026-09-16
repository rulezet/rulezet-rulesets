rule TTP_XOR_WriteProcessMemory_f2bc {
  strings:
    $key_f2bc = { a5 ce [2] 97 ec [2] 91 d9 [2] bf d9 [2] 80 c5 }

  condition:
    any of them
}