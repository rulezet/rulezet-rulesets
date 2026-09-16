rule TTP_XOR_WriteProcessMemory_d332 {
  strings:
    $key_d332 = { 84 40 [2] b6 62 [2] b0 57 [2] 9e 57 [2] a1 4b }

  condition:
    any of them
}