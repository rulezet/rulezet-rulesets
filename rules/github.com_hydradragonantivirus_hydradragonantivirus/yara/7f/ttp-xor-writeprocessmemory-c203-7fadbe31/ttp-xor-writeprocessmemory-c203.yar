rule TTP_XOR_WriteProcessMemory_c203 {
  strings:
    $key_c203 = { 95 71 [2] a7 53 [2] a1 66 [2] 8f 66 [2] b0 7a }

  condition:
    any of them
}