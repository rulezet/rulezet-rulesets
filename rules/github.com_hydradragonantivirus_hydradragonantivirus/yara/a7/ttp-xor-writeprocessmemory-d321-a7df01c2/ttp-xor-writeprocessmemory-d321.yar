rule TTP_XOR_WriteProcessMemory_d321 {
  strings:
    $key_d321 = { 84 53 [2] b6 71 [2] b0 44 [2] 9e 44 [2] a1 58 }

  condition:
    any of them
}