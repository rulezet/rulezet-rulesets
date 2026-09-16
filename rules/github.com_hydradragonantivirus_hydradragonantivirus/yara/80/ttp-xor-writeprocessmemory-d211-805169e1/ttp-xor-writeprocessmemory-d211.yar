rule TTP_XOR_WriteProcessMemory_d211 {
  strings:
    $key_d211 = { 85 63 [2] b7 41 [2] b1 74 [2] 9f 74 [2] a0 68 }

  condition:
    any of them
}