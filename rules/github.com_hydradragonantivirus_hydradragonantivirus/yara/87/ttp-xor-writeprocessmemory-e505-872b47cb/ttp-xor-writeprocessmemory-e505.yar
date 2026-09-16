rule TTP_XOR_WriteProcessMemory_e505 {
  strings:
    $key_e505 = { b2 77 [2] 80 55 [2] 86 60 [2] a8 60 [2] 97 7c }

  condition:
    any of them
}