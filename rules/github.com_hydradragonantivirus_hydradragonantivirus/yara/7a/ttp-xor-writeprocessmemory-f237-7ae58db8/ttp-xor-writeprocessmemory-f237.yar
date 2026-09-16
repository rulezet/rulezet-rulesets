rule TTP_XOR_WriteProcessMemory_f237 {
  strings:
    $key_f237 = { a5 45 [2] 97 67 [2] 91 52 [2] bf 52 [2] 80 4e }

  condition:
    any of them
}