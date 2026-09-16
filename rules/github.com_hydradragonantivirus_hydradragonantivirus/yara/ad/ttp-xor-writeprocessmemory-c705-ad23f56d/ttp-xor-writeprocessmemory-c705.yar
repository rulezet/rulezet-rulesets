rule TTP_XOR_WriteProcessMemory_c705 {
  strings:
    $key_c705 = { 90 77 [2] a2 55 [2] a4 60 [2] 8a 60 [2] b5 7c }

  condition:
    any of them
}