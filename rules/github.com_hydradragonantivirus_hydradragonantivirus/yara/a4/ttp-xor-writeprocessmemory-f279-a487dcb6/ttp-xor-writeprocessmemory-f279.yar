rule TTP_XOR_WriteProcessMemory_f279 {
  strings:
    $key_f279 = { a5 0b [2] 97 29 [2] 91 1c [2] bf 1c [2] 80 00 }

  condition:
    any of them
}