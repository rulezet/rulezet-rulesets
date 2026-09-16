rule TTP_XOR_WriteProcessMemory_d522 {
  strings:
    $key_d522 = { 82 50 [2] b0 72 [2] b6 47 [2] 98 47 [2] a7 5b }

  condition:
    any of them
}