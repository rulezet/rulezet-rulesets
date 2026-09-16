rule TTP_XOR_WriteProcessMemory_c213 {
  strings:
    $key_c213 = { 95 61 [2] a7 43 [2] a1 76 [2] 8f 76 [2] b0 6a }

  condition:
    any of them
}