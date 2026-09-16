rule TTP_XOR_WriteProcessMemory_cbd0 {
  strings:
    $key_cbd0 = { 9c a2 [2] ae 80 [2] a8 b5 [2] 86 b5 [2] b9 a9 }

  condition:
    any of them
}