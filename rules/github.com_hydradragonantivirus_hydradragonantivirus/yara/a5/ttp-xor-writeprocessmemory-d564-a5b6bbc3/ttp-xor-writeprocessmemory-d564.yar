rule TTP_XOR_WriteProcessMemory_d564 {
  strings:
    $key_d564 = { 82 16 [2] b0 34 [2] b6 01 [2] 98 01 [2] a7 1d }

  condition:
    any of them
}