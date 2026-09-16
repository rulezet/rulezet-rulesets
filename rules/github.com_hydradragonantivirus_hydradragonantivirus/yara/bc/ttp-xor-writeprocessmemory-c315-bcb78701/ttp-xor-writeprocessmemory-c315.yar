rule TTP_XOR_WriteProcessMemory_c315 {
  strings:
    $key_c315 = { 94 67 [2] a6 45 [2] a0 70 [2] 8e 70 [2] b1 6c }

  condition:
    any of them
}