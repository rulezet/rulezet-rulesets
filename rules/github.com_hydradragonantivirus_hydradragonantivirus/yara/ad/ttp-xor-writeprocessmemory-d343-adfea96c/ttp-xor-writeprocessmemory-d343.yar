rule TTP_XOR_WriteProcessMemory_d343 {
  strings:
    $key_d343 = { 84 31 [2] b6 13 [2] b0 26 [2] 9e 26 [2] a1 3a }

  condition:
    any of them
}