rule TTP_XOR_WriteProcessMemory_c015 {
  strings:
    $key_c015 = { 97 67 [2] a5 45 [2] a3 70 [2] 8d 70 [2] b2 6c }

  condition:
    any of them
}