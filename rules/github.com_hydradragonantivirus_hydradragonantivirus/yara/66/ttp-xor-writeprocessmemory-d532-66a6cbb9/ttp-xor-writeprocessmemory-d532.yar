rule TTP_XOR_WriteProcessMemory_d532 {
  strings:
    $key_d532 = { 82 40 [2] b0 62 [2] b6 57 [2] 98 57 [2] a7 4b }

  condition:
    any of them
}