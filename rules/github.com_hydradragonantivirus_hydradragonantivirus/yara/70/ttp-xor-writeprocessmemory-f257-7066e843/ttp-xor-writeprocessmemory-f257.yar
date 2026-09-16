rule TTP_XOR_WriteProcessMemory_f257 {
  strings:
    $key_f257 = { a5 25 [2] 97 07 [2] 91 32 [2] bf 32 [2] 80 2e }

  condition:
    any of them
}