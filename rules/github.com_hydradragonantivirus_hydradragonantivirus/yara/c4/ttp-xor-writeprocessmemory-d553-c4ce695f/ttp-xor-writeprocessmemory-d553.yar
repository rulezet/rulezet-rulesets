rule TTP_XOR_WriteProcessMemory_d553 {
  strings:
    $key_d553 = { 82 21 [2] b0 03 [2] b6 36 [2] 98 36 [2] a7 2a }

  condition:
    any of them
}