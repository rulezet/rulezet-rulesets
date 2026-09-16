rule TTP_XOR_WriteProcessMemory_c575 {
  strings:
    $key_c575 = { 92 07 [2] a0 25 [2] a6 10 [2] 88 10 [2] b7 0c }

  condition:
    any of them
}