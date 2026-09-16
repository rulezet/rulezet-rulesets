rule TTP_XOR_WriteProcessMemory_c175 {
  strings:
    $key_c175 = { 96 07 [2] a4 25 [2] a2 10 [2] 8c 10 [2] b3 0c }

  condition:
    any of them
}