rule TTP_XOR_WriteProcessMemory_d353 {
  strings:
    $key_d353 = { 84 21 [2] b6 03 [2] b0 36 [2] 9e 36 [2] a1 2a }

  condition:
    any of them
}