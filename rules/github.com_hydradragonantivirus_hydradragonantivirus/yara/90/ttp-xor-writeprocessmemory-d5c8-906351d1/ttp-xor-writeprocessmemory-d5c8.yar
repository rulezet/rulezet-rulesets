rule TTP_XOR_WriteProcessMemory_d5c8 {
  strings:
    $key_d5c8 = { 82 ba [2] b0 98 [2] b6 ad [2] 98 ad [2] a7 b1 }

  condition:
    any of them
}