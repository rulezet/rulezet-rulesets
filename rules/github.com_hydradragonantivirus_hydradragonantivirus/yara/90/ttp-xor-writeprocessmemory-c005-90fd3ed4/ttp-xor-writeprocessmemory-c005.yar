rule TTP_XOR_WriteProcessMemory_c005 {
  strings:
    $key_c005 = { 97 77 [2] a5 55 [2] a3 60 [2] 8d 60 [2] b2 7c }

  condition:
    any of them
}