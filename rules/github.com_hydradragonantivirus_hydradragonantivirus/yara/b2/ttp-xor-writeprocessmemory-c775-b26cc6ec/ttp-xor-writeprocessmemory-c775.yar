rule TTP_XOR_WriteProcessMemory_c775 {
  strings:
    $key_c775 = { 90 07 [2] a2 25 [2] a4 10 [2] 8a 10 [2] b5 0c }

  condition:
    any of them
}