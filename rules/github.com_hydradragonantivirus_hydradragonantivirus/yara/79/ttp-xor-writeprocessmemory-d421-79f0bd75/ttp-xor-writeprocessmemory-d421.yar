rule TTP_XOR_WriteProcessMemory_d421 {
  strings:
    $key_d421 = { 83 53 [2] b1 71 [2] b7 44 [2] 99 44 [2] a6 58 }

  condition:
    any of them
}