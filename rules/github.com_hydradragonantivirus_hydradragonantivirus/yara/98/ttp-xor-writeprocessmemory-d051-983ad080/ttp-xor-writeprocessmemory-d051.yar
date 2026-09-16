rule TTP_XOR_WriteProcessMemory_d051 {
  strings:
    $key_d051 = { 87 23 [2] b5 01 [2] b3 34 [2] 9d 34 [2] a2 28 }

  condition:
    any of them
}