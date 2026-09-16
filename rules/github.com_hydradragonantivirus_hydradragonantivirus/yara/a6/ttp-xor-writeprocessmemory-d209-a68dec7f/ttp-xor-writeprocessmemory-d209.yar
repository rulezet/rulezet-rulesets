rule TTP_XOR_WriteProcessMemory_d209 {
  strings:
    $key_d209 = { 85 7b [2] b7 59 [2] b1 6c [2] 9f 6c [2] a0 70 }

  condition:
    any of them
}