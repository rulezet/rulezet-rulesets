rule TTP_XOR_WriteProcessMemory_d764 {
  strings:
    $key_d764 = { 80 16 [2] b2 34 [2] b4 01 [2] 9a 01 [2] a5 1d }

  condition:
    any of them
}