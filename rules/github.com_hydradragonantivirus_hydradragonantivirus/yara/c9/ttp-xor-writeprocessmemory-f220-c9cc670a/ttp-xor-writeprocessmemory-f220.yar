rule TTP_XOR_WriteProcessMemory_f220 {
  strings:
    $key_f220 = { a5 52 [2] 97 70 [2] 91 45 [2] bf 45 [2] 80 59 }

  condition:
    any of them
}