rule TTP_XOR_WriteProcessMemory_d573 {
  strings:
    $key_d573 = { 82 01 [2] b0 23 [2] b6 16 [2] 98 16 [2] a7 0a }

  condition:
    any of them
}