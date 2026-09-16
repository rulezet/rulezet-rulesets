rule TTP_XOR_WriteProcessMemory_d525 {
  strings:
    $key_d525 = { 82 57 [2] b0 75 [2] b6 40 [2] 98 40 [2] a7 5c }

  condition:
    any of them
}