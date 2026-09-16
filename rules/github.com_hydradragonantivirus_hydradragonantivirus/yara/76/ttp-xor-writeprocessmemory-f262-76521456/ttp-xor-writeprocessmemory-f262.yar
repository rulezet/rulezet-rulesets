rule TTP_XOR_WriteProcessMemory_f262 {
  strings:
    $key_f262 = { a5 10 [2] 97 32 [2] 91 07 [2] bf 07 [2] 80 1b }

  condition:
    any of them
}