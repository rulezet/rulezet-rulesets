rule TTP_XOR_WriteProcessMemory_c5c8 {
  strings:
    $key_c5c8 = { 92 ba [2] a0 98 [2] a6 ad [2] 88 ad [2] b7 b1 }

  condition:
    any of them
}