rule TTP_XOR_WriteProcessMemory_d415 {
  strings:
    $key_d415 = { 83 67 [2] b1 45 [2] b7 70 [2] 99 70 [2] a6 6c }

  condition:
    any of them
}