rule TTP_XOR_WriteProcessMemory_c202 {
  strings:
    $key_c202 = { 95 70 [2] a7 52 [2] a1 67 [2] 8f 67 [2] b0 7b }

  condition:
    any of them
}