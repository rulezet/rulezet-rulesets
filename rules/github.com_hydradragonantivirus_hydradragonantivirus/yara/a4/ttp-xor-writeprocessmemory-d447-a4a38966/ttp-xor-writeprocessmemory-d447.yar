rule TTP_XOR_WriteProcessMemory_d447 {
  strings:
    $key_d447 = { 83 35 [2] b1 17 [2] b7 22 [2] 99 22 [2] a6 3e }

  condition:
    any of them
}