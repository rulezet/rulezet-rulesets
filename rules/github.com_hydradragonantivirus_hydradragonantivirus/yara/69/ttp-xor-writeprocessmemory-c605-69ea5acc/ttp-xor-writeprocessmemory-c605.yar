rule TTP_XOR_WriteProcessMemory_c605 {
  strings:
    $key_c605 = { 91 77 [2] a3 55 [2] a5 60 [2] 8b 60 [2] b4 7c }

  condition:
    any of them
}