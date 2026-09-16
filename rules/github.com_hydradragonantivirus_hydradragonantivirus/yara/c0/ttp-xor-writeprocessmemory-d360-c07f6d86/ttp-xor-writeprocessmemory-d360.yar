rule TTP_XOR_WriteProcessMemory_d360 {
  strings:
    $key_d360 = { 84 12 [2] b6 30 [2] b0 05 [2] 9e 05 [2] a1 19 }

  condition:
    any of them
}