rule TTP_XOR_WriteProcessMemory_f2ed {
  strings:
    $key_f2ed = { a5 9f [2] 97 bd [2] 91 88 [2] bf 88 [2] 80 94 }

  condition:
    any of them
}