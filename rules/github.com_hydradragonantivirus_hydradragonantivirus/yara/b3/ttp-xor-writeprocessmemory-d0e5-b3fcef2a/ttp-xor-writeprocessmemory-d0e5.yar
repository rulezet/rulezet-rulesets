rule TTP_XOR_WriteProcessMemory_d0e5 {
  strings:
    $key_d0e5 = { 87 97 [2] b5 b5 [2] b3 80 [2] 9d 80 [2] a2 9c }

  condition:
    any of them
}