rule TTP_XOR_WriteProcessMemory_d264 {
  strings:
    $key_d264 = { 85 16 [2] b7 34 [2] b1 01 [2] 9f 01 [2] a0 1d }

  condition:
    any of them
}