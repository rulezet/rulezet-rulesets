rule TTP_XOR_WriteProcessMemory_d213 {
  strings:
    $key_d213 = { 85 61 [2] b7 43 [2] b1 76 [2] 9f 76 [2] a0 6a }

  condition:
    any of them
}