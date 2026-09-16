rule TTP_XOR_WriteProcessMemory_d221 {
  strings:
    $key_d221 = { 85 53 [2] b7 71 [2] b1 44 [2] 9f 44 [2] a0 58 }

  condition:
    any of them
}