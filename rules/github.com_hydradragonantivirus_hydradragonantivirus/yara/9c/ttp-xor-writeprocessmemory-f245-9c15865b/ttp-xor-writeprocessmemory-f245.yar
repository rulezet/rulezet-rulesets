rule TTP_XOR_WriteProcessMemory_f245 {
  strings:
    $key_f245 = { a5 37 [2] 97 15 [2] 91 20 [2] bf 20 [2] 80 3c }

  condition:
    any of them
}