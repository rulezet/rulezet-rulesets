rule TTP_XOR_WriteProcessMemory_d554 {
  strings:
    $key_d554 = { 82 26 [2] b0 04 [2] b6 31 [2] 98 31 [2] a7 2d }

  condition:
    any of them
}