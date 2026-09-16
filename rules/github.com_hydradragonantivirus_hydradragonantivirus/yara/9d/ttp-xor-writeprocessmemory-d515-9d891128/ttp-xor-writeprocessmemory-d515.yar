rule TTP_XOR_WriteProcessMemory_d515 {
  strings:
    $key_d515 = { 82 67 [2] b0 45 [2] b6 70 [2] 98 70 [2] a7 6c }

  condition:
    any of them
}