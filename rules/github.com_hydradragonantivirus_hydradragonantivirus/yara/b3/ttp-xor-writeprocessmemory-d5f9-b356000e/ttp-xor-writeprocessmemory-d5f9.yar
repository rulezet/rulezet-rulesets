rule TTP_XOR_WriteProcessMemory_d5f9 {
  strings:
    $key_d5f9 = { 82 8b [2] b0 a9 [2] b6 9c [2] 98 9c [2] a7 80 }

  condition:
    any of them
}