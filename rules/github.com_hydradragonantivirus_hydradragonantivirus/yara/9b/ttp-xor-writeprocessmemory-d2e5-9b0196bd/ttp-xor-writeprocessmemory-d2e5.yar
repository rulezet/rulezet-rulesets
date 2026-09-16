rule TTP_XOR_WriteProcessMemory_d2e5 {
  strings:
    $key_d2e5 = { 85 97 [2] b7 b5 [2] b1 80 [2] 9f 80 [2] a0 9c }

  condition:
    any of them
}