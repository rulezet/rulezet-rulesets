rule TTP_XOR_WriteProcessMemory_f432 {
  strings:
    $key_f432 = { a3 40 [2] 91 62 [2] 97 57 [2] b9 57 [2] 86 4b }

  condition:
    any of them
}