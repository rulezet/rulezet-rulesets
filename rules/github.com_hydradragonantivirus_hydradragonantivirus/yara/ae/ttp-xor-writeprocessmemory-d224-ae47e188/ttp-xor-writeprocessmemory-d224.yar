rule TTP_XOR_WriteProcessMemory_d224 {
  strings:
    $key_d224 = { 85 56 [2] b7 74 [2] b1 41 [2] 9f 41 [2] a0 5d }

  condition:
    any of them
}