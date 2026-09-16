rule TTP_XOR_WriteProcessMemory_f443 {
  strings:
    $key_f443 = { a3 31 [2] 91 13 [2] 97 26 [2] b9 26 [2] 86 3a }

  condition:
    any of them
}