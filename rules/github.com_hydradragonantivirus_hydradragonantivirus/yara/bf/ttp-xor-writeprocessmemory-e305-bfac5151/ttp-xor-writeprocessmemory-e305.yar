rule TTP_XOR_WriteProcessMemory_e305 {
  strings:
    $key_e305 = { b4 77 [2] 86 55 [2] 80 60 [2] ae 60 [2] 91 7c }

  condition:
    any of them
}