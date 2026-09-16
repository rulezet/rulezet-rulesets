rule TTP_XOR_WriteProcessMemory_f450 {
  strings:
    $key_f450 = { a3 22 [2] 91 00 [2] 97 35 [2] b9 35 [2] 86 29 }

  condition:
    any of them
}