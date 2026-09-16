rule TTP_XOR_WriteProcessMemory_d473 {
  strings:
    $key_d473 = { 83 01 [2] b1 23 [2] b7 16 [2] 99 16 [2] a6 0a }

  condition:
    any of them
}