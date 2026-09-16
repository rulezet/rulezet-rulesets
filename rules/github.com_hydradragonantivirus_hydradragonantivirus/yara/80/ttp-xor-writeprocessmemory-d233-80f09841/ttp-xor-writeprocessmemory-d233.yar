rule TTP_XOR_WriteProcessMemory_d233 {
  strings:
    $key_d233 = { 85 41 [2] b7 63 [2] b1 56 [2] 9f 56 [2] a0 4a }

  condition:
    any of them
}