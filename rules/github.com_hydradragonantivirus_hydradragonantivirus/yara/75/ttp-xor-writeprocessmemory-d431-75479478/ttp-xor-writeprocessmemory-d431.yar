rule TTP_XOR_WriteProcessMemory_d431 {
  strings:
    $key_d431 = { 83 43 [2] b1 61 [2] b7 54 [2] 99 54 [2] a6 48 }

  condition:
    any of them
}