rule TTP_XOR_WriteProcessMemory_d540 {
  strings:
    $key_d540 = { 82 32 [2] b0 10 [2] b6 25 [2] 98 25 [2] a7 39 }

  condition:
    any of them
}