rule TTP_XOR_WriteProcessMemory_cae5 {
  strings:
    $key_cae5 = { 9d 97 [2] af b5 [2] a9 80 [2] 87 80 [2] b8 9c }

  condition:
    any of them
}