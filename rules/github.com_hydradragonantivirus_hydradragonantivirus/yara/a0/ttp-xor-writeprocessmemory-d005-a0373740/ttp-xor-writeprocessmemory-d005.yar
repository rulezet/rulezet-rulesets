rule TTP_XOR_WriteProcessMemory_d005 {
  strings:
    $key_d005 = { 87 77 [2] b5 55 [2] b3 60 [2] 9d 60 [2] a2 7c }

  condition:
    any of them
}