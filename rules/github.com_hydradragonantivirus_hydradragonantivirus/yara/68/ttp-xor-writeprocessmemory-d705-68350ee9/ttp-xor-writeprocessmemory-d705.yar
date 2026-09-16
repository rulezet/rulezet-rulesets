rule TTP_XOR_WriteProcessMemory_d705 {
  strings:
    $key_d705 = { 80 77 [2] b2 55 [2] b4 60 [2] 9a 60 [2] a5 7c }

  condition:
    any of them
}